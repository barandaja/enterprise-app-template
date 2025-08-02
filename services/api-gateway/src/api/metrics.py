"""
Metrics and monitoring endpoints for the API Gateway.
Provides Prometheus-compatible metrics and performance statistics.
"""
import time
from typing import Dict, Any, List
from fastapi import APIRouter, Request, Response
from fastapi.responses import PlainTextResponse
import structlog

from ..core.config import get_settings
from ..core.redis import redis_manager
from ..services.rate_limiter import RateLimiterManager, RateLimitType

logger = structlog.get_logger()
settings = get_settings()

router = APIRouter(tags=["metrics"])


class PrometheusMetrics:
    """Prometheus metrics formatter."""
    
    @staticmethod
    def format_metric(name: str, value: float, labels: Dict[str, str] = None, help_text: str = None) -> str:
        """Format a single metric in Prometheus format."""
        lines = []
        
        if help_text:
            lines.append(f"# HELP {name} {help_text}")
            lines.append(f"# TYPE {name} gauge")
        
        if labels:
            label_str = ",".join([f'{k}="{v}"' for k, v in labels.items()])
            lines.append(f"{name}{{{label_str}}} {value}")
        else:
            lines.append(f"{name} {value}")
        
        return "\n".join(lines)
    
    @staticmethod
    def format_counter(name: str, value: int, labels: Dict[str, str] = None, help_text: str = None) -> str:
        """Format a counter metric."""
        lines = []
        
        if help_text:
            lines.append(f"# HELP {name} {help_text}")
            lines.append(f"# TYPE {name} counter")
        
        if labels:
            label_str = ",".join([f'{k}="{v}"' for k, v in labels.items()])
            lines.append(f"{name}{{{label_str}}} {value}")
        else:
            lines.append(f"{name} {value}")
        
        return "\n".join(lines)
    
    @staticmethod
    def format_histogram(name: str, buckets: Dict[str, float], labels: Dict[str, str] = None, help_text: str = None) -> str:
        """Format a histogram metric."""
        lines = []
        
        if help_text:
            lines.append(f"# HELP {name} {help_text}")
            lines.append(f"# TYPE {name} histogram")
        
        base_labels = labels or {}
        
        for bucket, value in buckets.items():
            bucket_labels = {**base_labels, "le": bucket}
            label_str = ",".join([f'{k}="{v}"' for k, v in bucket_labels.items()])
            lines.append(f"{name}_bucket{{{label_str}}} {value}")
        
        return "\n".join(lines)


@router.get("/metrics")
async def prometheus_metrics(request: Request):
    """Prometheus-compatible metrics endpoint."""
    if not settings.metrics_enabled:
        return PlainTextResponse("Metrics collection is disabled", status_code=404)
    
    metrics_lines = []
    
    try:
        # System metrics
        current_time = time.time()
        metrics_lines.append(
            PrometheusMetrics.format_metric(
                "gateway_uptime_seconds",
                current_time - getattr(request.app.state, 'start_time', current_time),
                help_text="Gateway uptime in seconds"
            )
        )
        
        # Service registry metrics
        try:
            service_registry = request.app.state.service_registry
            services_status = await service_registry.get_all_services_status()
            
            healthy_count = len([s for s in services_status.values() if s["status"] == "healthy"])
            unhealthy_count = len([s for s in services_status.values() if s["status"] == "unhealthy"])
            
            metrics_lines.append(
                PrometheusMetrics.format_metric(
                    "gateway_backend_services_healthy",
                    healthy_count,
                    help_text="Number of healthy backend services"
                )
            )
            
            metrics_lines.append(
                PrometheusMetrics.format_metric(
                    "gateway_backend_services_unhealthy",
                    unhealthy_count,
                    help_text="Number of unhealthy backend services"
                )
            )
            
            # Per-service metrics
            for service_name, service_info in services_status.items():
                labels = {"service": service_name}
                
                metrics_lines.append(
                    PrometheusMetrics.format_metric(
                        "gateway_service_healthy",
                        1 if service_info["status"] == "healthy" else 0,
                        labels=labels,
                        help_text="Service health status (1=healthy, 0=unhealthy)"
                    )
                )
                
                if service_info.get("response_time"):
                    metrics_lines.append(
                        PrometheusMetrics.format_metric(
                            "gateway_service_response_time_seconds",
                            service_info["response_time"],
                            labels=labels,
                            help_text="Service response time in seconds"
                        )
                    )
                
                metrics_lines.append(
                    PrometheusMetrics.format_counter(
                        "gateway_service_consecutive_failures",
                        service_info.get("consecutive_failures", 0),
                        labels=labels,
                        help_text="Consecutive failures for service"
                    )
                )
        
        except Exception as e:
            logger.error("Failed to collect service registry metrics", error=str(e))
        
        # Circuit breaker metrics
        try:
            circuit_breaker_manager = request.app.state.circuit_breaker_manager
            cb_states = await circuit_breaker_manager.get_all_states()
            
            for service_name, cb_info in cb_states.items():
                labels = {"service": service_name}
                
                state_value = {"closed": 0, "half_open": 1, "open": 2}.get(cb_info.get("state"), -1)
                metrics_lines.append(
                    PrometheusMetrics.format_metric(
                        "gateway_circuit_breaker_state",
                        state_value,
                        labels=labels,
                        help_text="Circuit breaker state (0=closed, 1=half_open, 2=open)"
                    )
                )
                
                metrics_lines.append(
                    PrometheusMetrics.format_counter(
                        "gateway_circuit_breaker_failures",
                        cb_info.get("failure_count", 0),
                        labels=labels,
                        help_text="Circuit breaker failure count"
                    )
                )
                
                metrics_lines.append(
                    PrometheusMetrics.format_counter(
                        "gateway_circuit_breaker_successes",
                        cb_info.get("success_count", 0),
                        labels=labels,
                        help_text="Circuit breaker success count"
                    )
                )
        
        except Exception as e:
            logger.error("Failed to collect circuit breaker metrics", error=str(e))
        
        # Rate limiting metrics
        try:
            rate_limiter_manager = request.app.state.rate_limiter_manager
            rate_limit_stats = await rate_limiter_manager.get_global_rate_limit_stats()
            
            metrics_lines.append(
                PrometheusMetrics.format_metric(
                    "gateway_rate_limit_total_keys",
                    rate_limit_stats.get("total_keys", 0),
                    help_text="Total number of rate limit keys"
                )
            )
            
            for limit_type, count in rate_limit_stats.get("by_type", {}).items():
                metrics_lines.append(
                    PrometheusMetrics.format_metric(
                        "gateway_rate_limit_keys_by_type",
                        count,
                        labels={"type": limit_type},
                        help_text="Rate limit keys by type"
                    )
                )
        
        except Exception as e:
            logger.error("Failed to collect rate limiting metrics", error=str(e))
        
        # Redis metrics
        try:
            redis_stats = await redis_manager.get_connection_stats()
            
            for stat_name, stat_value in redis_stats.items():
                metrics_lines.append(
                    PrometheusMetrics.format_metric(
                        f"gateway_redis_{stat_name}",
                        stat_value,
                        help_text=f"Redis {stat_name.replace('_', ' ')}"
                    )
                )
        
        except Exception as e:
            logger.error("Failed to collect Redis metrics", error=str(e))
        
        # Request metrics from recent data
        try:
            # Get metrics from last 5 minutes
            current_minute = int(current_time // 60)
            request_counts = {}
            response_times = []
            status_codes = {}
            
            for minute_offset in range(5):
                minute_key = current_minute - minute_offset
                metrics_pattern = f"metrics:{minute_key}:*"
                
                # This is simplified - in production you'd use Redis SCAN
                # and aggregate the data properly
                pass
            
            # Add placeholder metrics
            metrics_lines.append(
                PrometheusMetrics.format_counter(
                    "gateway_requests_total",
                    0,  # Would be calculated from Redis data
                    labels={"method": "GET", "status": "200"},
                    help_text="Total number of requests"
                )
            )
            
            metrics_lines.append(
                PrometheusMetrics.format_metric(
                    "gateway_request_duration_seconds",
                    0.0,  # Would be calculated from Redis data
                    help_text="Request duration in seconds"
                )
            )
        
        except Exception as e:
            logger.error("Failed to collect request metrics", error=str(e))
        
        # Join all metrics
        response_content = "\n\n".join(metrics_lines)
        
        return PlainTextResponse(
            content=response_content,
            media_type="text/plain; version=0.0.4; charset=utf-8"
        )
    
    except Exception as e:
        logger.error("Failed to generate metrics", error=str(e))
        return PlainTextResponse("Error generating metrics", status_code=500)


@router.get("/metrics/json")
async def json_metrics(request: Request):
    """JSON format metrics for custom monitoring systems."""
    
    metrics_data = {
        "timestamp": int(time.time()),
        "gateway": {
            "uptime": time.time() - getattr(request.app.state, 'start_time', time.time()),
            "version": "1.0.0"
        },
        "services": {},
        "circuit_breakers": {},
        "rate_limiting": {},
        "system": {}
    }
    
    try:
        # Service metrics
        service_registry = request.app.state.service_registry
        services_status = await service_registry.get_all_services_status()
        
        metrics_data["services"] = {
            "total": len(services_status),
            "healthy": len([s for s in services_status.values() if s["status"] == "healthy"]),
            "unhealthy": len([s for s in services_status.values() if s["status"] == "unhealthy"]),
            "details": services_status
        }
        
        # Circuit breaker metrics
        circuit_breaker_manager = request.app.state.circuit_breaker_manager
        cb_health = await circuit_breaker_manager.health_check()
        cb_states = await circuit_breaker_manager.get_all_states()
        
        metrics_data["circuit_breakers"] = {
            "health": cb_health,
            "states": cb_states
        }
        
        # Rate limiting metrics
        rate_limiter_manager = request.app.state.rate_limiter_manager
        rate_limit_stats = await rate_limiter_manager.get_global_rate_limit_stats()
        
        metrics_data["rate_limiting"] = rate_limit_stats
        
        # System metrics
        redis_stats = await redis_manager.get_connection_stats()
        metrics_data["system"]["redis"] = redis_stats
    
    except Exception as e:
        logger.error("Failed to collect JSON metrics", error=str(e))
        metrics_data["error"] = str(e)
    
    return metrics_data


@router.get("/metrics/performance")
async def performance_metrics(request: Request):
    """Performance-focused metrics."""
    
    try:
        # Collect performance data from last hour
        current_time = time.time()
        performance_data = {
            "timestamp": int(current_time),
            "request_stats": {
                "total_requests": 0,
                "avg_response_time": 0.0,
                "p95_response_time": 0.0,
                "p99_response_time": 0.0,
                "error_rate": 0.0
            },
            "service_performance": {},
            "rate_limit_stats": {
                "total_rate_limited": 0,
                "rate_limit_by_type": {}
            }
        }
        
        # Get service response times
        service_registry = request.app.state.service_registry
        services_status = await service_registry.get_all_services_status()
        
        for service_name, service_info in services_status.items():
            if service_info.get("response_time"):
                performance_data["service_performance"][service_name] = {
                    "avg_response_time": service_info["response_time"],
                    "consecutive_failures": service_info.get("consecutive_failures", 0),
                    "consecutive_successes": service_info.get("consecutive_successes", 0),
                    "health_status": service_info["status"]
                }
        
        return performance_data
    
    except Exception as e:
        logger.error("Failed to collect performance metrics", error=str(e))
        return {
            "error": str(e),
            "timestamp": int(time.time())
        }


@router.get("/metrics/health-score")
async def health_score(request: Request):
    """Calculate overall health score for the gateway."""
    
    try:
        scores = {
            "services": 0,
            "circuit_breakers": 0,
            "rate_limiting": 0,
            "system": 0
        }
        
        # Service health score (40% weight)
        service_registry = request.app.state.service_registry
        services_status = await service_registry.get_all_services_status()
        
        if services_status:
            healthy_count = len([s for s in services_status.values() if s["status"] == "healthy"])
            scores["services"] = (healthy_count / len(services_status)) * 40
        
        # Circuit breaker health score (20% weight)
        circuit_breaker_manager = request.app.state.circuit_breaker_manager
        cb_health = await circuit_breaker_manager.health_check()
        
        if cb_health["health"] == "healthy":
            scores["circuit_breakers"] = 20
        elif cb_health["open_breakers"] / max(cb_health["total_breakers"], 1) < 0.5:
            scores["circuit_breakers"] = 10
        
        # Rate limiting health score (20% weight)
        # Assume healthy if no errors in rate limiting
        scores["rate_limiting"] = 20
        
        # System health score (20% weight)
        redis_healthy = await redis_manager.health_check()
        scores["system"] = 20 if redis_healthy else 0
        
        total_score = sum(scores.values())
        
        health_grade = "A"
        if total_score < 90:
            health_grade = "B"
        if total_score < 80:
            health_grade = "C"
        if total_score < 70:
            health_grade = "D"
        if total_score < 60:
            health_grade = "F"
        
        return {
            "overall_score": total_score,
            "grade": health_grade,
            "component_scores": scores,
            "status": "healthy" if total_score >= 70 else "unhealthy",
            "timestamp": int(time.time())
        }
    
    except Exception as e:
        logger.error("Failed to calculate health score", error=str(e))
        return {
            "overall_score": 0,
            "grade": "F",
            "error": str(e),
            "timestamp": int(time.time())
        }