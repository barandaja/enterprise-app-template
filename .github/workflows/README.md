# CI/CD Pipeline Documentation

This directory contains comprehensive GitHub Actions workflows for the enterprise application template. The pipeline implements industry best practices for security, quality, and automated deployments.

## 📋 Workflow Overview

### 1. Frontend CI/CD (`frontend-ci-cd.yml`)
**Triggers**: Push/PR to `main`/`develop` with changes in `frontend/`

**Key Features**:
- **Security**: npm audit, dependency vulnerability scanning
- **Quality**: ESLint, TypeScript strict mode, Prettier formatting
- **Testing**: Unit tests (Vitest), E2E tests (Playwright) across multiple browsers
- **Performance**: Lighthouse CI analysis
- **Build**: Multi-environment builds (dev/staging/prod)
- **Deploy**: Automated deployment to AWS S3 + CloudFront

**Artifacts Generated**:
- Build artifacts for each environment
- Test coverage reports
- Security scan results
- Performance metrics

### 2. Backend CI/CD (`backend-ci-cd.yml`)
**Triggers**: Push/PR to `main`/`develop` with changes in `services/`, `backend/`, or `shared/python-commons/`

**Key Features**:
- **Change Detection**: Only builds/tests modified services
- **Security**: Bandit, Safety, Semgrep scanning
- **Quality**: Black, isort, flake8, mypy, pylint
- **Testing**: pytest with coverage across Python 3.11 and 3.12
- **Performance**: Load testing with Locust
- **Build**: Multi-architecture Docker images
- **Deploy**: Blue-green Kubernetes deployments

**Matrix Strategy**: Runs tests for `auth-service`, `api-gateway`, and `user-service`

### 3. Security Scanning (`security-scan.yml`)
**Triggers**: Push/PR, daily schedule (2 AM UTC), manual dispatch

**Comprehensive Security Coverage**:
- **SAST**: CodeQL analysis for TypeScript and Python
- **Dependency Scanning**: npm audit, Safety, pip-audit, OSV-Scanner
- **Container Security**: Trivy and Grype vulnerability scanning
- **IaC Security**: Checkov, TFSec, Kubesec for infrastructure
- **Secret Detection**: TruffleHog and GitLeaks
- **OWASP**: Dependency Check with CVE database

**Reporting**: Consolidated security report with SARIF uploads to GitHub Security

### 4. Code Quality & Coverage (`code-quality.yml`)
**Triggers**: Push/PR, weekly schedule (Sunday 3 AM UTC)

**Quality Metrics**:
- **Frontend**: ESLint analysis, TypeScript strict mode, bundle size analysis
- **Backend**: Pylint scoring, complexity analysis (Radon), dead code detection (Vulture)
- **Coverage**: Comprehensive test coverage with thresholds
- **Quality Gate**: Automated pass/fail based on configurable metrics

**Integration**: SonarQube support (if configured)

### 5. Automated Release (`release.yml`)
**Triggers**: Push to `main`, tag creation, manual dispatch

**Release Process**:
- **Pre-validation**: Full test suite execution
- **Version Management**: Conventional commits or manual versioning
- **Artifact Creation**: Frontend builds and Docker images
- **GitHub Release**: Automated changelog generation
- **Container Registry**: Multi-architecture image publishing
- **Production Deployment**: Blue-green Kubernetes deployment
- **Post-release**: Slack notifications, documentation updates

## 🔒 Security Configuration Required

### GitHub Secrets
```bash
# AWS Deployment
AWS_ACCESS_KEY_ID=<aws-access-key>
AWS_SECRET_ACCESS_KEY=<aws-secret-key>

# Container Registry (automatically available)
GITHUB_TOKEN=<github-token>

# Code Coverage
CODECOV_TOKEN=<codecov-token>

# Notifications
SLACK_WEBHOOK=<slack-webhook-url>

# Security Scanning (optional)
GITLEAKS_LICENSE=<gitleaks-license>
SONAR_TOKEN=<sonarqube-token>

# Lighthouse CI (optional)
LHCI_GITHUB_APP_TOKEN=<lighthouse-token>
```

### GitHub Variables
```bash
# AWS Configuration
AWS_REGION=us-west-2
DEV_S3_BUCKET=your-dev-bucket
STAGING_S3_BUCKET=your-staging-bucket  
PROD_S3_BUCKET=your-prod-bucket
DEV_CLOUDFRONT_ID=E1234567890
STAGING_CLOUDFRONT_ID=E0987654321
PROD_CLOUDFRONT_ID=E1122334455

# Kubernetes Clusters
DEV_CLUSTER_NAME=dev-cluster
STAGING_CLUSTER_NAME=staging-cluster
PROD_CLUSTER_NAME=prod-cluster

# SonarQube (optional)
SONAR_HOST_URL=https://sonarqube.yourcompany.com
```

## 🚀 Deployment Strategy

### Environment Flow
1. **Development**: Auto-deploy from `develop` branch
2. **Staging**: Auto-deploy from `main` branch  
3. **Production**: Deploy from tagged releases (`v*`)

### Deployment Features
- **Blue-Green Deployments**: Zero-downtime production deployments
- **Health Checks**: Automatic rollback on failed health checks
- **Smoke Tests**: Post-deployment validation
- **Infrastructure as Code**: Kubernetes manifests with Kustomize

## 📊 Quality Gates

### Frontend Thresholds
- Test coverage: ≥80%
- ESLint errors: 0
- TypeScript strict mode: Pass
- Bundle size: Monitored

### Backend Thresholds  
- Test coverage: ≥70%
- Pylint score: ≥7.0/10
- Security issues: 0 high severity
- Complex functions: ≤5 per service

### Security Thresholds
- Critical vulnerabilities: 0
- High vulnerabilities: ≤5
- Container security: Pass Trivy scan
- IaC security: Pass Checkov/TFSec

## 🛠️ Customization Points

### 1. Modify Quality Thresholds
Edit threshold values in `code-quality.yml`:
```yaml
# Example: Lower coverage requirement
if coverage_pct < 60:  # Was 70
    print('::warning::Code coverage below 60%')
```

### 2. Add/Remove Security Tools
In `security-scan.yml`, comment out tools you don't need:
```yaml
# - name: Run Semgrep
#   if: false  # Disable Semgrep
```

### 3. Environment-Specific Configuration
Update deployment targets in workflow files:
```yaml
deploy-staging:
  if: github.ref == 'refs/heads/main'  # Change trigger branch
```

### 4. Service-Specific Settings
Modify the service matrix in `backend-ci-cd.yml`:
```yaml
strategy:
  matrix:
    service: [auth-service, api-gateway, user-service, new-service]
```

## 🐛 Troubleshooting

### Common Issues

1. **Build Failures**
   - Check dependency versions in `package.json`/`requirements.txt`
   - Verify Docker base images are up to date
   - Review test database connectivity

2. **Security Scan Failures**
   - Update vulnerable dependencies
   - Review and whitelist false positives
   - Check secret scanning for leaked credentials

3. **Deployment Failures**
   - Verify AWS credentials and permissions
   - Check Kubernetes cluster connectivity
   - Review S3 bucket policies and CloudFront distributions

4. **Quality Gate Failures**
   - Review test coverage reports
   - Fix linting errors before merging
   - Address high-complexity functions

### Debug Commands
```bash
# Local testing
npm run test:coverage           # Frontend coverage
pytest --cov=src tests/        # Backend coverage
docker build -t test .         # Docker build test
kubectl apply --dry-run=client # K8s manifest validation
```

## 📈 Monitoring & Observability

### Workflow Metrics
- **Build Duration**: Track build time trends
- **Test Success Rate**: Monitor test reliability  
- **Deployment Frequency**: Release velocity metrics
- **Security Issues**: Vulnerability trend analysis

### Alerts Configuration
Set up GitHub branch protection rules:
```yaml
required_status_checks:
  strict: true
  contexts:
    - "Frontend CI/CD"
    - "Backend CI/CD" 
    - "Security Scanning"
    - "Code Quality"
```

## 🔄 Maintenance

### Weekly Tasks
- Review security scan results
- Update dependency versions
- Monitor quality trends
- Clean up old artifacts

### Monthly Tasks  
- Update action versions in workflows
- Review and adjust quality thresholds
- Audit access permissions
- Update documentation

### Quarterly Tasks
- Security audit of entire pipeline
- Performance optimization review
- Disaster recovery testing
- Tool evaluation and updates

## 📚 Additional Resources

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Container Security Best Practices](https://kubernetes.io/docs/concepts/security/)
- [OWASP CI/CD Security](https://owasp.org/www-project-devsecops-guideline/)
- [Conventional Commits](https://www.conventionalcommits.org/)

## 🆘 Critical Review Points for Reviewers

### Security Concerns
1. **Secret Management**: Ensure all secrets are properly configured in GitHub settings
2. **Access Controls**: Review IAM permissions for AWS deployment accounts
3. **Image Security**: Verify base images are from trusted sources
4. **Network Security**: Check Kubernetes network policies

### Performance Considerations  
1. **Resource Limits**: Review Docker container resource constraints
2. **Caching Strategy**: Validate cache keys and dependencies
3. **Parallel Execution**: Ensure matrix builds don't overwhelm runners
4. **Artifact Retention**: Balance storage costs with audit requirements

### Reliability Issues
1. **Error Handling**: Review failure scenarios and rollback procedures
2. **Dependencies**: Check for single points of failure in external services
3. **Timeout Values**: Ensure realistic timeouts for all operations
4. **Health Checks**: Validate deployment health check logic

### Compliance Requirements
1. **Audit Trails**: Verify all actions are logged appropriately
2. **Data Handling**: Review artifact storage and data retention policies
3. **Access Logging**: Ensure deployment access is tracked
4. **Change Management**: Validate approval processes for production deployments

### Cost Optimization
1. **Runner Usage**: Review job concurrency and resource allocation
2. **Storage Costs**: Evaluate artifact retention periods
3. **External Services**: Monitor usage of third-party tools (CodeCov, etc.)
4. **Infrastructure**: Review cloud resource provisioning

## ✅ Pre-Production Checklist

- [ ] All required secrets configured in GitHub
- [ ] AWS IAM roles and policies created
- [ ] Kubernetes clusters provisioned and accessible
- [ ] S3 buckets and CloudFront distributions created
- [ ] Branch protection rules enabled
- [ ] Team notifications configured (Slack)
- [ ] Quality gate thresholds reviewed and approved
- [ ] Security scanning tools configured
- [ ] Monitoring and alerting set up
- [ ] Documentation reviewed and updated