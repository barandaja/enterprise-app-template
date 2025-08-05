import React from 'react';
import { 
  BarChart3, 
  Users, 
  TrendingUp, 
  DollarSign,
  ArrowUpRight,
  ArrowDownRight,
  Activity,
  Calendar,
  Clock
} from 'lucide-react';
import type { PageProps } from '../types';

interface StatCardProps {
  title: string;
  value: string;
  change?: string;
  changeType?: 'positive' | 'negative';
  icon: React.ComponentType<{ className?: string }>;
}

function StatCard({ title, value, change, changeType, icon: Icon }: StatCardProps) {
  return (
    <div className="card hover-lift">
      <div className="card-content">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium text-muted-foreground">
              {title}
            </p>
            <div className="flex items-center space-x-2">
              <p className="text-2xl font-bold">
                {value}
              </p>
              {change && (
                <div className={`flex items-center text-xs ${
                  changeType === 'positive' 
                    ? 'text-green-600 dark:text-green-400' 
                    : 'text-red-600 dark:text-red-400'
                }`}>
                  {changeType === 'positive' ? (
                    <ArrowUpRight className="h-3 w-3" />
                  ) : (
                    <ArrowDownRight className="h-3 w-3" />
                  )}
                  <span>{change}</span>
                </div>
              )}
            </div>
          </div>
          <div className="h-12 w-12 rounded-lg bg-primary/10 flex items-center justify-center">
            <Icon className="h-6 w-6 text-primary" />
          </div>
        </div>
      </div>
    </div>
  );
}

interface RecentActivityItem {
  id: string;
  title: string;
  description: string;
  time: string;
  type: 'success' | 'warning' | 'info';
}

const recentActivities: RecentActivityItem[] = [
  {
    id: '1',
    title: 'New user registered',
    description: 'John Doe created an account',
    time: '2 minutes ago',
    type: 'success'
  },
  {
    id: '2',
    title: 'System backup completed',
    description: 'Daily backup finished successfully',
    time: '1 hour ago',
    type: 'info'
  },
  {
    id: '3',
    title: 'Low storage warning',
    description: 'Server storage is 85% full',
    time: '3 hours ago',
    type: 'warning'
  },
  {
    id: '4',
    title: 'Performance report generated',
    description: 'Monthly analytics report is ready',
    time: '5 hours ago',
    type: 'info'
  }
];

function Dashboard({ className }: PageProps) {
  return (
    <div className="container py-8">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-foreground mb-2">
          Dashboard
        </h1>
        <p className="text-muted-foreground">
          Welcome back! Here's what's happening with your business today.
        </p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <StatCard
          title="Total Revenue"
          value="$45,231"
          change="+20.1%"
          changeType="positive"
          icon={DollarSign}
        />
        <StatCard
          title="Active Users"
          value="2,350"
          change="+180"
          changeType="positive"
          icon={Users}
        />
        <StatCard
          title="Conversion Rate"
          value="3.42%"
          change="-2.4%"
          changeType="negative"
          icon={TrendingUp}
        />
        <StatCard
          title="Total Orders"
          value="1,234"
          change="+12.5%"
          changeType="positive"
          icon={BarChart3}
        />
      </div>

      {/* Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Chart placeholder */}
        <div className="lg:col-span-2">
          <div className="card">
            <div className="card-header">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="card-title">Revenue Overview</h3>
                  <p className="card-description">
                    Monthly revenue trend for the last 6 months
                  </p>
                </div>
                <div className="flex items-center space-x-2">
                  <button className="btn-outline btn-sm">
                    <Calendar className="h-4 w-4" />
                    Last 6 months
                  </button>
                </div>
              </div>
            </div>
            <div className="card-content">
              {/* Placeholder for chart */}
              <div className="h-80 bg-muted/50 rounded-lg flex items-center justify-center">
                <div className="text-center text-muted-foreground">
                  <BarChart3 className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>Chart component would go here</p>
                  <p className="text-sm">Integration with Chart.js or Recharts recommended</p>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Recent Activity */}
        <div className="card">
          <div className="card-header">
            <div className="flex items-center space-x-2">
              <Activity className="h-5 w-5" />
              <h3 className="card-title">Recent Activity</h3>
            </div>
            <p className="card-description">
              Latest updates from your system
            </p>
          </div>
          <div className="card-content">
            <div className="space-y-4">
              {recentActivities.map((activity) => (
                <div key={activity.id} className="flex items-start space-x-3">
                  <div className={`h-2 w-2 rounded-full mt-2 flex-shrink-0 ${
                    activity.type === 'success' 
                      ? 'bg-green-500' 
                      : activity.type === 'warning'
                      ? 'bg-yellow-500'
                      : 'bg-blue-500'
                  }`} />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-foreground">
                      {activity.title}
                    </p>
                    <p className="text-xs text-muted-foreground truncate">
                      {activity.description}
                    </p>
                    <div className="flex items-center text-xs text-muted-foreground mt-1">
                      <Clock className="h-3 w-3 mr-1" />
                      {activity.time}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div className="card-footer">
            <button className="btn-ghost btn-sm w-full">
              View all activities
            </button>
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="mt-8">
        <h2 className="text-xl font-semibold mb-4">Quick Actions</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <button className="card hover-scale text-left p-4">
            <div className="flex items-center space-x-3">
              <div className="h-10 w-10 rounded-lg bg-blue-100 dark:bg-blue-900/20 flex items-center justify-center">
                <Users className="h-5 w-5 text-blue-600 dark:text-blue-400" />
              </div>
              <div>
                <p className="font-medium">Add User</p>
                <p className="text-sm text-muted-foreground">Create new account</p>
              </div>
            </div>
          </button>

          <button className="card hover-scale text-left p-4">
            <div className="flex items-center space-x-3">
              <div className="h-10 w-10 rounded-lg bg-green-100 dark:bg-green-900/20 flex items-center justify-center">
                <BarChart3 className="h-5 w-5 text-green-600 dark:text-green-400" />
              </div>
              <div>
                <p className="font-medium">Generate Report</p>
                <p className="text-sm text-muted-foreground">Create analytics report</p>
              </div>
            </div>
          </button>

          <button className="card hover-scale text-left p-4">
            <div className="flex items-center space-x-3">
              <div className="h-10 w-10 rounded-lg bg-purple-100 dark:bg-purple-900/20 flex items-center justify-center">
                <TrendingUp className="h-5 w-5 text-purple-600 dark:text-purple-400" />
              </div>
              <div>
                <p className="font-medium">View Analytics</p>
                <p className="text-sm text-muted-foreground">Check performance</p>
              </div>
            </div>
          </button>

          <button className="card hover-scale text-left p-4">
            <div className="flex items-center space-x-3">
              <div className="h-10 w-10 rounded-lg bg-orange-100 dark:bg-orange-900/20 flex items-center justify-center">
                <DollarSign className="h-5 w-5 text-orange-600 dark:text-orange-400" />
              </div>
              <div>
                <p className="font-medium">Financial Overview</p>
                <p className="text-sm text-muted-foreground">Review finances</p>
              </div>
            </div>
          </button>
        </div>
      </div>
    </div>
  );
}

export default Dashboard;