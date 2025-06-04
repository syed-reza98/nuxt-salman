---
title: "Deploying a LAMP Stack Application on AWS Elastic Beanstalk - Step-by-Step Guide"
description: "A comprehensive guide to deploying a LAMP (Linux, Apache, MySQL, PHP) stack application on AWS Elastic Beanstalk with custom AMI, security groups, load balancing, auto-scaling, RDS multi-AZ, and email notifications."
date: "2025-06-04"
tags: ["AWS", "LAMP", "Elastic Beanstalk", "DevOps", "PHP", "MySQL", "Infrastructure"]
author: "syed-reza98"
readTime: "15 min read"
featured: true
---

# Deploying a LAMP Stack Application on AWS Elastic Beanstalk - Step-by-Step Guide

I'll guide you through deploying a LAMP (Linux, Apache, MySQL, PHP) stack application on AWS Elastic Beanstalk using AWS CLI commands. This guide covers all your requirements including custom AMI, security groups, load balancing, auto-scaling, RDS with multi-AZ, custom VPC, and email notifications.

## Prerequisites

Before we begin, ensure you have:

1. AWS CLI installed and configured with appropriate credentials
2. Basic understanding of AWS services
3. A LAMP stack application ready for deployment
4. An AWS account with necessary permissions

## Step 1: Create a Custom Key Pair

First, let's create a key pair for secure SSH access to our instances:

```bash
aws ec2 create-key-pair --key-name lamp-app-key --query 'KeyMaterial' --output text > lamp-app-key.pem
chmod 400 lamp-app-key.pem
```

This creates a new key pair and saves the private key to a file with proper permissions.

## Step 2: Create a Custom VPC with Public Subnets

We'll create a custom VPC to have full control over our network configuration:

```bash
# Create VPC
aws ec2 create-vpc --cidr-block 10.0.0.0/16 --tag-specifications 'ResourceType=vpc,Tags=[{Key=Name,Value=lamp-app-vpc}]' --query 'Vpc.VpcId' --output text > vpc-id.txt
VPC_ID=$(cat vpc-id.txt)

# Enable DNS hostnames for the VPC
aws ec2 modify-vpc-attribute --vpc-id $VPC_ID --enable-dns-hostnames '{"Value":true}'

# Create Internet Gateway and attach to VPC
aws ec2 create-internet-gateway --tag-specifications 'ResourceType=internet-gateway,Tags=[{Key=Name,Value=lamp-app-igw}]' --query 'InternetGateway.InternetGatewayId' --output text > igw-id.txt
IGW_ID=$(cat igw-id.txt)
aws ec2 attach-internet-gateway --vpc-id $VPC_ID --internet-gateway-id $IGW_ID

# Create public subnets in different AZs
aws ec2 create-subnet --vpc-id $VPC_ID --cidr-block 10.0.1.0/24 --availability-zone us-east-1a --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=lamp-app-subnet-1a}]' --query 'Subnet.SubnetId' --output text > subnet1-id.txt
aws ec2 create-subnet --vpc-id $VPC_ID --cidr-block 10.0.2.0/24 --availability-zone us-east-1b --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=lamp-app-subnet-1b}]' --query 'Subnet.SubnetId' --output text > subnet2-id.txt
SUBNET1_ID=$(cat subnet1-id.txt)
SUBNET2_ID=$(cat subnet2-id.txt)

# Enable auto-assign public IPs for subnets
aws ec2 modify-subnet-attribute --subnet-id $SUBNET1_ID --map-public-ip-on-launch
aws ec2 modify-subnet-attribute --subnet-id $SUBNET2_ID --map-public-ip-on-launch

# Create a route table and associate with subnets
aws ec2 create-route-table --vpc-id $VPC_ID --tag-specifications 'ResourceType=route-table,Tags=[{Key=Name,Value=lamp-app-rtb}]' --query 'RouteTable.RouteTableId' --output text > rtb-id.txt
RTB_ID=$(cat rtb-id.txt)

# Create route to Internet Gateway
aws ec2 create-route --route-table-id $RTB_ID --destination-cidr-block 0.0.0.0/0 --gateway-id $IGW_ID

# Associate subnets with route table
aws ec2 associate-route-table --subnet-id $SUBNET1_ID --route-table-id $RTB_ID
aws ec2 associate-route-table --subnet-id $SUBNET2_ID --route-table-id $RTB_ID
```

## Step 3: Create Custom Security Groups

Security groups act as virtual firewalls for our instances:

```bash
# Create security group for LAMP instances
aws ec2 create-security-group --group-name lamp-app-sg --description "Security group for LAMP application" --vpc-id $VPC_ID --query 'GroupId' --output text > sg-id.txt
SG_ID=$(cat sg-id.txt)

# Add inbound rules for HTTP and SSH
aws ec2 authorize-security-group-ingress --group-id $SG_ID --protocol tcp --port 80 --cidr 0.0.0.0/0 --description "Allow HTTP from anywhere"
aws ec2 authorize-security-group-ingress --group-id $SG_ID --protocol tcp --port 22 --cidr 0.0.0.0/0 --description "Allow SSH from anywhere"

# Create security group for RDS
aws ec2 create-security-group --group-name lamp-app-db-sg --description "Security group for LAMP RDS instance" --vpc-id $VPC_ID --query 'GroupId' --output text > db-sg-id.txt
DB_SG_ID=$(cat db-sg-id.txt)

# Allow MySQL connections from the LAMP app security group
aws ec2 authorize-security-group-ingress --group-id $DB_SG_ID --protocol tcp --port 3306 --source-group $SG_ID --description "Allow MySQL from LAMP instances"
```

## Step 4: Create a Custom AMI

We'll create a custom AMI with our LAMP stack pre-installed:

```bash
# Launch a temporary instance to create a custom AMI
aws ec2 run-instances \
  --image-id ami-0c55b159cbfafe1f0 \
  --instance-type t2.micro \
  --key-name lamp-app-key \
  --security-group-ids $SG_ID \
  --subnet-id $SUBNET1_ID \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=lamp-ami-builder}]' \
  --query 'Instances[0].InstanceId' \
  --output text > temp-instance-id.txt

TEMP_INSTANCE_ID=$(cat temp-instance-id.txt)

# Wait for the instance to be running
echo "Waiting for the instance to be running..."
aws ec2 wait instance-running --instance-ids $TEMP_INSTANCE_ID

# Get the public IP of the instance
PUBLIC_IP=$(aws ec2 describe-instances --instance-ids $TEMP_INSTANCE_ID --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
echo "Instance is running at IP: $PUBLIC_IP"
```

Now, SSH into the instance and install the LAMP stack:

```bash
# Connect to the instance
ssh -i lamp-app-key.pem ec2-user@$PUBLIC_IP

# Update packages
sudo yum update -y

# Install Apache
sudo yum install -y httpd
sudo systemctl start httpd
sudo systemctl enable httpd

# Install MySQL
sudo yum install -y mysql-server
sudo systemctl start mysqld
sudo systemctl enable mysqld

# Install PHP
sudo amazon-linux-extras install -y php7.4
sudo yum install -y php-mysqlnd

# Install additional PHP extensions
sudo yum install -y php-mbstring php-xml php-gd php-pdo

# Create a basic PHP info file
echo "<?php phpinfo(); ?>" | sudo tee /var/www/html/info.php

# Exit SSH
exit
```

After setting up the LAMP stack, create an AMI:

```bash
# Create AMI from the configured instance
aws ec2 create-image --instance-id $TEMP_INSTANCE_ID --name "LAMP-Stack-Custom-AMI" --description "Custom AMI for LAMP Stack application" --query 'ImageId' --output text > ami-id.txt
AMI_ID=$(cat ami-id.txt)

# Wait for AMI to be available
echo "Waiting for AMI to be available..."
aws ec2 wait image-available --image-ids $AMI_ID

# Terminate the temporary instance
aws ec2 terminate-instances --instance-ids $TEMP_INSTANCE_ID
```

## Step 5: Create an RDS Database with Multi-AZ

Set up a highly available MySQL database:

```bash
# Create a DB subnet group
aws rds create-db-subnet-group \
  --db-subnet-group-name lamp-app-db-subnet-group \
  --db-subnet-group-description "Subnet group for LAMP app RDS" \
  --subnet-ids "[$SUBNET1_ID, $SUBNET2_ID]"

# Create RDS instance with Multi-AZ deployment
aws rds create-db-instance \
  --db-instance-identifier lamp-app-db \
  --db-name lampapp \
  --engine mysql \
  --master-username lampdbadmin \
  --master-user-password "YourStrongPassword123!" \
  --db-instance-class db.t3.small \
  --allocated-storage 20 \
  --vpc-security-group-ids $DB_SG_ID \
  --db-subnet-group-name lamp-app-db-subnet-group \
  --multi-az \
  --backup-retention-period 7 \
  --query 'DBInstance.Endpoint.Address' \
  --output text > db-endpoint.txt

# Wait for DB instance to be available
echo "Waiting for RDS instance to be available (this may take several minutes)..."
aws rds wait db-instance-available --db-instance-identifier lamp-app-db

DB_ENDPOINT=$(cat db-endpoint.txt)
echo "RDS endpoint: $DB_ENDPOINT"
```

## Step 6: Create Elastic Beanstalk Application

```bash
# Create the Elastic Beanstalk application
aws elasticbeanstalk create-application \
  --application-name lamp-application \
  --description "LAMP Stack Application"
```

## Step 7: Prepare Configuration Options

Create a comprehensive configuration file for your Elastic Beanstalk environment:

```bash
# Create configuration options file
cat > eb-options.json << EOF
[
  {
    "Namespace": "aws:autoscaling:launchconfiguration",
    "OptionName": "SecurityGroups",
    "Value": "$SG_ID"
  },
  {
    "Namespace": "aws:autoscaling:launchconfiguration",
    "OptionName": "EC2KeyName",
    "Value": "lamp-app-key"
  },
  {
    "Namespace": "aws:autoscaling:launchconfiguration",
    "OptionName": "IamInstanceProfile",
    "Value": "aws-elasticbeanstalk-ec2-role"
  },
  {
    "Namespace": "aws:autoscaling:launchconfiguration",
    "OptionName": "ImageId",
    "Value": "$AMI_ID"
  },
  {
    "Namespace": "aws:elasticbeanstalk:environment",
    "OptionName": "EnvironmentType",
    "Value": "LoadBalanced"
  },
  {
    "Namespace": "aws:autoscaling:asg",
    "OptionName": "MinSize",
    "Value": "2"
  },
  {
    "Namespace": "aws:autoscaling:asg",
    "OptionName": "MaxSize",
    "Value": "8"
  },
  {
    "Namespace": "aws:autoscaling:trigger",
    "OptionName": "MeasureName",
    "Value": "NetworkOut"
  },
  {
    "Namespace": "aws:autoscaling:trigger",
    "OptionName": "Unit",
    "Value": "Bytes/Second"
  },
  {
    "Namespace": "aws:autoscaling:trigger",
    "OptionName": "UpperThreshold",
    "Value": "60"
  },
  {
    "Namespace": "aws:autoscaling:trigger",
    "OptionName": "LowerThreshold",
    "Value": "30"
  },
  {
    "Namespace": "aws:ec2:vpc",
    "OptionName": "VPCId",
    "Value": "$VPC_ID"
  },
  {
    "Namespace": "aws:ec2:vpc",
    "OptionName": "Subnets",
    "Value": "$SUBNET1_ID,$SUBNET2_ID"
  },
  {
    "Namespace": "aws:ec2:vpc",
    "OptionName": "ELBSubnets",
    "Value": "$SUBNET1_ID,$SUBNET2_ID"
  },
  {
    "Namespace": "aws:elasticbeanstalk:application:environment",
    "OptionName": "RDS_HOSTNAME",
    "Value": "$DB_ENDPOINT"
  },
  {
    "Namespace": "aws:elasticbeanstalk:application:environment",
    "OptionName": "RDS_PORT",
    "Value": "3306"
  },
  {
    "Namespace": "aws:elasticbeanstalk:application:environment",
    "OptionName": "RDS_DB_NAME",
    "Value": "lampapp"
  },
  {
    "Namespace": "aws:elasticbeanstalk:application:environment",
    "OptionName": "RDS_USERNAME",
    "Value": "lampdbadmin"
  },
  {
    "Namespace": "aws:elasticbeanstalk:application:environment",
    "OptionName": "RDS_PASSWORD",
    "Value": "YourStrongPassword123!"
  },
  {
    "Namespace": "aws:elasticbeanstalk:sns:topics",
    "OptionName": "Notification Endpoint",
    "Value": "your.email@example.com"
  },
  {
    "Namespace": "aws:elasticbeanstalk:sns:topics",
    "OptionName": "Notification Protocol",
    "Value": "email"
  }
]
EOF
```

## Step 8: Prepare Your Application Bundle

Create a sample PHP application that demonstrates database connectivity:

```bash
# Create application directory structure
mkdir -p lamp-app/public

# Create main application file
cat > lamp-app/public/index.php << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>LAMP Stack on AWS Elastic Beanstalk</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }
        .container { max-width: 800px; margin: 0 auto; }
        h1 { color: #0066cc; }
        .success { color: green; }
        .error { color: red; }
        pre { background: #f4f4f4; padding: 10px; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>LAMP Stack on AWS Elastic Beanstalk</h1>
        <h2>Environment Information:</h2>
        <pre>
<?php
echo "Server: " . $_SERVER['SERVER_NAME'] . "\n";
echo "PHP Version: " . phpversion() . "\n";
echo "Date: " . date('Y-m-d H:i:s') . "\n";
?>
        </pre>

        <h2>Database Connection Test:</h2>
<?php
// Use environment variables from Elastic Beanstalk
$dbhost = getenv('RDS_HOSTNAME');
$dbport = getenv('RDS_PORT');
$dbname = getenv('RDS_DB_NAME');
$username = getenv('RDS_USERNAME');
$password = getenv('RDS_PASSWORD');

try {
    $dsn = "mysql:host=$dbhost;port=$dbport;dbname=$dbname";
    $conn = new PDO($dsn, $username, $password);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    echo "<p class='success'>Connected to database successfully!</p>";

    // Create a test table if it doesn't exist
    $sql = "CREATE TABLE IF NOT EXISTS test_table (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(50) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )";
    $conn->exec($sql);
    echo "<p>Test table created or already exists.</p>";

    // Insert a record
    $sql = "INSERT INTO test_table (name) VALUES ('Test Entry " . time() . "')";
    $conn->exec($sql);
    echo "<p>Added a test record.</p>";

    // Query the table
    $stmt = $conn->query("SELECT id, name, created_at FROM test_table ORDER BY id DESC LIMIT 10");
    echo "<h3>Last 10 entries:</h3>";
    echo "<ul>";
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        echo "<li>ID: " . $row['id'] . " - Name: " . $row['name'] . " - Created: " . $row['created_at'] . "</li>";
    }
    echo "</ul>";

} catch(PDOException $e) {
    echo "<p class='error'>Database connection failed: " . $e->getMessage() . "</p>";
}
?>
    </div>
</body>
</html>
EOF

# Create .htaccess file
cat > lamp-app/.htaccess << EOF
DirectoryIndex public/index.php
EOF

# Create .ebextensions directory for custom configurations
mkdir -p lamp-app/.ebextensions

# Create Apache configuration
cat > lamp-app/.ebextensions/01_apache.config << EOF
files:
    "/etc/httpd/conf.d/ssl.conf":
        mode: "000644"
        owner: root
        group: root
        content: |
            LoadModule ssl_module modules/mod_ssl.so
            Listen 443
            <VirtualHost *:443>
                ServerName localhost
                SSLEngine on
                SSLCertificateFile "/etc/pki/tls/certs/localhost.crt"
                SSLCertificateKeyFile "/etc/pki/tls/private/localhost.key"
                DocumentRoot /var/www/html
                <Directory /var/www/html>
                    AllowOverride All
                    Require all granted
                </Directory>
            </VirtualHost>

commands:
    01_create_cert:
        command: "mkdir -p /etc/pki/tls/certs /etc/pki/tls/private && openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/pki/tls/private/localhost.key -out /etc/pki/tls/certs/localhost.crt -subj \"/C=US/ST=State/L=City/O=Organization/CN=localhost\""
EOF

# Create application bundle
cd lamp-app
zip -r ../lamp-app.zip *
cd ..
```

## Step 9: Deploy to Elastic Beanstalk

```bash
# Create S3 bucket for application versions
aws s3 mb s3://lamp-app-versions-$(date +%s)
BUCKET_NAME="lamp-app-versions-$(date +%s)"

# Upload application to S3
aws s3 cp lamp-app.zip s3://$BUCKET_NAME/

# Create application version
aws elasticbeanstalk create-application-version \
  --application-name lamp-application \
  --version-label lamp-v1 \
  --source-bundle S3Bucket="$BUCKET_NAME",S3Key="lamp-app.zip"

# Create configuration template
aws elasticbeanstalk create-configuration-template \
  --application-name lamp-application \
  --template-name lamp-app-template \
  --solution-stack-name "64bit Amazon Linux 2 v3.3.13 running PHP 7.4" \
  --option-settings file://eb-options.json

# Create the environment
aws elasticbeanstalk create-environment \
  --application-name lamp-application \
  --environment-name lamp-production \
  --template-name lamp-app-template \
  --version-label lamp-v1 \
  --description "Production environment for LAMP stack application"

# Wait for environment to be ready
echo "Waiting for environment to be ready (this may take several minutes)..."
aws elasticbeanstalk wait environment-updated --environment-name lamp-production --version-label lamp-v1

# Get environment URL
ENV_URL=$(aws elasticbeanstalk describe-environments --environment-names lamp-production --query 'Environments[0].CNAME' --output text)
echo "Your application is deployed at: http://$ENV_URL"
```

## Step 10: Configure Email Notifications

Set up email notifications for important events:

```bash
# Update environment with notification settings
aws elasticbeanstalk update-environment \
  --environment-name lamp-production \
  --option-settings '[
    {
      "Namespace": "aws:elasticbeanstalk:sns:topics",
      "OptionName": "Notification Endpoint",
      "Value": "your.email@example.com"
    },
    {
      "Namespace": "aws:elasticbeanstalk:sns:topics",
      "OptionName": "Notification Protocol",
      "Value": "email"
    }
  ]'
```

## Step 11: Verify Your Deployment

After deployment, verify everything is working correctly:

```bash
# Check environment health
aws elasticbeanstalk describe-environment-health --environment-name lamp-production --attribute-names All

# List instances in the environment
aws elasticbeanstalk describe-instances --environment-name lamp-production

# Check auto-scaling group
ASG_NAME=$(aws elasticbeanstalk describe-environment-resources --environment-name lamp-production --query 'EnvironmentResources.AutoScalingGroups[0].Name' --output text)
aws autoscaling describe-scaling-activities --auto-scaling-group-name $ASG_NAME
```

## Updating Your Application

To deploy updates to your application:

```bash
# Package your updated application
cd your-updated-app
zip -r ../lamp-app-v2.zip *
cd ..

# Upload to S3
aws s3 cp lamp-app-v2.zip s3://$BUCKET_NAME/

# Create new application version
aws elasticbeanstalk create-application-version \
  --application-name lamp-application \
  --version-label lamp-v2 \
  --source-bundle S3Bucket="$BUCKET_NAME",S3Key="lamp-app-v2.zip"

# Update environment with new version
aws elasticbeanstalk update-environment \
  --environment-name lamp-production \
  --version-label lamp-v2
```

## Key Features Implemented

This deployment includes:

✅ **Custom AMI** - Pre-configured with LAMP stack components
✅ **Custom VPC** - Full network control with public subnets across multiple AZs
✅ **Security Groups** - Properly configured for web and database access
✅ **Load Balancing** - Automatic traffic distribution across instances
✅ **Auto Scaling** - Scales from 2 to 8 instances based on network traffic
✅ **RDS Multi-AZ** - Highly available MySQL database with automatic failover
✅ **Custom Key Pairs** - Secure SSH access to instances
✅ **Email Notifications** - Alerts for environment events

## Best Practices

1. **Security**: Always use strong passwords and limit security group access
2. **Monitoring**: Set up CloudWatch alarms for additional monitoring
3. **Backups**: Configure automated RDS backups with appropriate retention
4. **SSL/TLS**: Consider using ACM certificates for HTTPS
5. **Cost Optimization**: Monitor usage and adjust instance types as needed

## Step 12: Enhanced Monitoring and Logging

Set up comprehensive monitoring for your LAMP stack:

```bash
# Create CloudWatch alarms for critical metrics
aws cloudwatch put-metric-alarm \
  --alarm-name "EB-HighCPUUtilization" \
  --alarm-description "Alarm when CPU exceeds 80%" \
  --metric-name CPUUtilization \
  --namespace AWS/EC2 \
  --statistic Average \
  --period 300 \
  --threshold 80 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 2

# Create alarm for RDS connections
aws cloudwatch put-metric-alarm \
  --alarm-name "RDS-HighConnections" \
  --alarm-description "Alarm when database connections exceed 80%" \
  --metric-name DatabaseConnections \
  --namespace AWS/RDS \
  --statistic Average \
  --period 300 \
  --threshold 80 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 2 \
  --dimensions Name=DBInstanceIdentifier,Value=lamp-app-db

# Enable Enhanced Monitoring for RDS
aws rds modify-db-instance \
  --db-instance-identifier lamp-app-db \
  --monitoring-interval 60 \
  --monitoring-role-arn arn:aws:iam::ACCOUNT-ID:role/rds-monitoring-role \
  --apply-immediately
```

## Step 13: Security Hardening

Implement additional security measures:

```bash
# Create IAM role for EC2 instances with minimal permissions
cat > trust-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

# Create security policy for instances
cat > instance-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "cloudwatch:PutMetricData"
      ],
      "Resource": "*"
    }
  ]
}
EOF

# Create IAM role
aws iam create-role \
  --role-name lamp-app-ec2-role \
  --assume-role-policy-document file://trust-policy.json

# Attach policy to role
aws iam put-role-policy \
  --role-name lamp-app-ec2-role \
  --policy-name lamp-app-policy \
  --policy-document file://instance-policy.json

# Create instance profile
aws iam create-instance-profile --instance-profile-name lamp-app-profile
aws iam add-role-to-instance-profile \
  --instance-profile-name lamp-app-profile \
  --role-name lamp-app-ec2-role

# Enable VPC Flow Logs for network monitoring
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids $VPC_ID \
  --traffic-type ALL \
  --log-destination-type cloud-watch-logs \
  --log-group-name VPCFlowLogs
```

### Security Configuration for .ebextensions

```bash
# Create security hardening configuration
cat > lamp-app/.ebextensions/02_security.config << EOF
files:
  "/tmp/security_hardening.sh":
    mode: "000755"
    owner: root
    group: root
    content: |
      #!/bin/bash
      # Disable unnecessary services
      systemctl disable telnet
      systemctl stop telnet

      # Configure firewall rules
      yum install -y iptables-services
      systemctl enable iptables

      # Set up fail2ban for SSH protection
      yum install -y epel-release
      yum install -y fail2ban
      systemctl enable fail2ban
      systemctl start fail2ban

      # Configure secure PHP settings
      sed -i 's/expose_php = On/expose_php = Off/' /etc/php.ini
      sed -i 's/display_errors = On/display_errors = Off/' /etc/php.ini
      sed -i 's/log_errors = Off/log_errors = On/' /etc/php.ini

      # Restart services
      systemctl restart httpd
      systemctl restart php-fpm

commands:
  01_run_security_hardening:
    command: "/tmp/security_hardening.sh"
EOF
```

## Step 14: Backup and Disaster Recovery

Implement comprehensive backup strategies:

```bash
# Create automated backup script
cat > backup-script.sh << 'EOF'
#!/bin/bash

# Variables
DB_IDENTIFIER="lamp-app-db"
BACKUP_PREFIX="lamp-app-backup"
RETENTION_DAYS=30

# Create manual RDS snapshot
SNAPSHOT_ID="${BACKUP_PREFIX}-$(date +%Y%m%d-%H%M%S)"
aws rds create-db-snapshot \
  --db-instance-identifier $DB_IDENTIFIER \
  --db-snapshot-identifier $SNAPSHOT_ID

echo "Created database snapshot: $SNAPSHOT_ID"

# Clean up old snapshots
OLD_SNAPSHOTS=$(aws rds describe-db-snapshots \
  --db-instance-identifier $DB_IDENTIFIER \
  --snapshot-type manual \
  --query "DBSnapshots[?SnapshotCreateTime<'$(date -d "$RETENTION_DAYS days ago" -Iso)'].DBSnapshotIdentifier" \
  --output text)

for snapshot in $OLD_SNAPSHOTS; do
  if [[ $snapshot == $BACKUP_PREFIX* ]]; then
    aws rds delete-db-snapshot --db-snapshot-identifier $snapshot
    echo "Deleted old snapshot: $snapshot"
  fi
done

# Backup application files to S3
aws s3 sync /var/www/html/ s3://lamp-app-backups/$(date +%Y/%m/%d)/
EOF

chmod +x backup-script.sh

# Create S3 bucket for backups
aws s3 mb s3://lamp-app-backups-$(date +%s)

# Set up automated backups using cron (add this to your .ebextensions)
cat > lamp-app/.ebextensions/03_backups.config << EOF
files:
  "/etc/cron.d/lamp-backup":
    mode: "000644"
    owner: root
    group: root
    content: |
      # Daily backup at 2 AM
      0 2 * * * root /home/ec2-user/backup-script.sh >> /var/log/backup.log 2>&1

  "/home/ec2-user/backup-script.sh":
    mode: "000755"
    owner: ec2-user
    group: ec2-user
    content: |
      #!/bin/bash
      # Application backup script
      aws s3 sync /var/www/html/ s3://lamp-app-backups/\$(date +\%Y/\%m/\%d)/

commands:
  01_start_cron:
    command: "service crond start && chkconfig crond on"
EOF
```

## Step 15: Cost Optimization

Implement cost-saving measures:

```bash
# Create cost optimization script
cat > cost-optimization.sh << 'EOF'
#!/bin/bash

# Set up scheduled scaling for non-production hours
# Scale down during off-hours (e.g., nights and weekends)

# Create scaling policy for scale down
aws autoscaling put-scaling-policy \
  --auto-scaling-group-name $(aws elasticbeanstalk describe-environment-resources \
    --environment-name lamp-production \
    --query 'EnvironmentResources.AutoScalingGroups[0].Name' --output text) \
  --policy-name "scale-down-policy" \
  --scaling-adjustment -1 \
  --adjustment-type "ChangeInCapacity" \
  --cooldown 300

# Create scaling policy for scale up
aws autoscaling put-scaling-policy \
  --auto-scaling-group-name $(aws elasticbeanstalk describe-environment-resources \
    --environment-name lamp-production \
    --query 'EnvironmentResources.AutoScalingGroups[0].Name' --output text) \
  --policy-name "scale-up-policy" \
  --scaling-adjustment 1 \
  --adjustment-type "ChangeInCapacity" \
  --cooldown 300

# Set up cost alerts
aws budgets create-budget \
  --account-id $(aws sts get-caller-identity --query Account --output text) \
  --budget '{
    "BudgetName": "LAMP-Stack-Monthly-Budget",
    "BudgetLimit": {
      "Amount": "100",
      "Unit": "USD"
    },
    "TimeUnit": "MONTHLY",
    "BudgetType": "COST"
  }' \
  --notifications-with-subscribers '[
    {
      "Notification": {
        "NotificationType": "ACTUAL",
        "ComparisonOperator": "GREATER_THAN",
        "Threshold": 80
      },
      "Subscribers": [
        {
          "SubscriptionType": "EMAIL",
          "Address": "your.email@example.com"
        }
      ]
    }
  ]'
EOF

chmod +x cost-optimization.sh
./cost-optimization.sh
```

### Cost Optimization Configuration

```bash
# Add cost optimization to .ebextensions
cat > lamp-app/.ebextensions/04_cost_optimization.config << EOF
option_settings:
  aws:autoscaling:launchconfiguration:
    InstanceType: t3.micro  # Use smaller instances for cost savings
  aws:autoscaling:asg:
    MinSize: 1  # Reduce minimum instances during off-peak
  aws:elasticbeanstalk:managedactions:
    ManagedActionsEnabled: true
    PreferredStartTime: "Sun:10:00"  # Schedule updates for low-traffic times
  aws:elasticbeanstalk:managedactions:platformupdate:
    UpdateLevel: minor
    InstanceRefreshEnabled: true
EOF
```

## Step 16: Performance Optimization

Enhance application performance:

```bash
# Create performance optimization configuration
cat > lamp-app/.ebextensions/05_performance.config << EOF
files:
  "/etc/httpd/conf.d/performance.conf":
    mode: "000644"
    owner: root
    group: root
    content: |
      # Enable compression
      LoadModule deflate_module modules/mod_deflate.so
      <Location />
        SetOutputFilter DEFLATE
        SetEnvIfNoCase Request_URI \
          \.(?:gif|jpe?g|png)$ no-gzip dont-vary
        SetEnvIfNoCase Request_URI \
          \.(?:exe|t?gz|zip|bz2|sit|rar)$ no-gzip dont-vary
      </Location>

      # Enable caching
      LoadModule expires_module modules/mod_expires.so
      <IfModule mod_expires.c>
        ExpiresActive On
        ExpiresByType text/css "access plus 1 month"
        ExpiresByType application/javascript "access plus 1 month"
        ExpiresByType image/png "access plus 1 month"
        ExpiresByType image/jpg "access plus 1 month"
        ExpiresByType image/jpeg "access plus 1 month"
        ExpiresByType image/gif "access plus 1 month"
      </IfModule>

      # Optimize KeepAlive
      KeepAlive On
      MaxKeepAliveRequests 100
      KeepAliveTimeout 15

  "/etc/php.d/performance.ini":
    mode: "000644"
    owner: root
    group: root
    content: |
      ; PHP Performance optimizations
      memory_limit = 256M
      max_execution_time = 30
      max_input_vars = 3000
      post_max_size = 32M
      upload_max_filesize = 32M

      ; OPcache settings
      opcache.enable=1
      opcache.memory_consumption=128
      opcache.interned_strings_buffer=8
      opcache.max_accelerated_files=4000
      opcache.revalidate_freq=2
      opcache.fast_shutdown=1

commands:
  01_restart_services:
    command: "systemctl restart httpd && systemctl restart php-fpm"
EOF
```

## Step 17: Database Performance Tuning

Optimize your RDS MySQL instance:

```bash
# Create parameter group for MySQL optimization
aws rds create-db-parameter-group \
  --db-parameter-group-name lamp-mysql-optimized \
  --db-parameter-group-family mysql8.0 \
  --description "Optimized parameters for LAMP application"

# Apply optimized parameters
aws rds modify-db-parameter-group \
  --db-parameter-group-name lamp-mysql-optimized \
  --parameters "ParameterName=innodb_buffer_pool_size,ParameterValue={DBInstanceClassMemory*3/4},ApplyMethod=pending-reboot" \
             "ParameterName=max_connections,ParameterValue=200,ApplyMethod=immediate" \
             "ParameterName=innodb_log_file_size,ParameterValue=134217728,ApplyMethod=pending-reboot" \
             "ParameterName=query_cache_type,ParameterValue=1,ApplyMethod=pending-reboot" \
             "ParameterName=query_cache_size,ParameterValue=67108864,ApplyMethod=pending-reboot"

# Apply parameter group to RDS instance
aws rds modify-db-instance \
  --db-instance-identifier lamp-app-db \
  --db-parameter-group-name lamp-mysql-optimized \
  --apply-immediately
```

## Step 18: SSL/TLS Certificate Setup

Secure your application with HTTPS:

```bash
# Request SSL certificate from ACM
aws acm request-certificate \
  --domain-name your-domain.com \
  --validation-method DNS \
  --subject-alternative-names "*.your-domain.com" \
  --query 'CertificateArn' \
  --output text > certificate-arn.txt

CERT_ARN=$(cat certificate-arn.txt)

# Configure HTTPS load balancer
cat > lamp-app/.ebextensions/06_https.config << EOF
option_settings:
  aws:elb:listener:443:
    ListenerProtocol: HTTPS
    InstancePort: 80
    InstanceProtocol: HTTP
    SSLCertificateId: $CERT_ARN
  aws:elb:listener:80:
    ListenerProtocol: HTTP
    InstancePort: 80
    InstanceProtocol: HTTP

files:
  "/etc/httpd/conf.d/ssl_redirect.conf":
    mode: "000644"
    owner: root
    group: root
    content: |
      RewriteEngine On
      RewriteCond %{HTTP:X-Forwarded-Proto} !https
      RewriteRule ^.*$ https://%{SERVER_NAME}%{REQUEST_URI} [R,L]
EOF
```

## Troubleshooting Common Issues

### Deployment Issues
- **Deployment failures**: Check Elastic Beanstalk logs in the AWS console
- **Timeout errors**: Increase deployment timeout in EB configuration
- **Version conflicts**: Ensure application bundle is properly structured

### Database Issues
- **Connection failures**: Verify security group rules and RDS endpoint
- **Slow queries**: Enable slow query log and optimize database queries
- **Connection pool exhaustion**: Adjust max_connections parameter

### Performance Issues
- **High CPU usage**: Monitor CloudWatch metrics and adjust scaling triggers
- **Memory issues**: Optimize PHP memory limits and enable OPcache
- **Network bottlenecks**: Review security group rules and load balancer settings

### Security Issues
- **SSL certificate errors**: Ensure proper certificate configuration in .ebextensions
- **Access denied errors**: Review IAM roles and security group permissions
- **Failed authentication**: Check RDS credentials and connection strings

## Cost Management Best Practices

1. **Right-sizing**: Use appropriate instance types based on actual usage
2. **Scheduled scaling**: Scale down during off-peak hours
3. **Reserved instances**: Purchase reserved instances for predictable workloads
4. **Monitoring**: Set up billing alerts and cost budgets
5. **Resource cleanup**: Regularly review and remove unused resources

## Maintenance and Updates

### Regular Maintenance Tasks

```bash
# Create maintenance script
cat > maintenance.sh << 'EOF'
#!/bin/bash

echo "Starting maintenance tasks..."

# Update system packages
sudo yum update -y

# Clear application logs older than 30 days
find /var/log -name "*.log" -type f -mtime +30 -delete

# Optimize database
mysql -h $RDS_HOSTNAME -u $RDS_USERNAME -p$RDS_PASSWORD -e "OPTIMIZE TABLE test_table;"

# Clear PHP OPcache
php -r "opcache_reset();"

# Restart services
sudo systemctl restart httpd
sudo systemctl restart php-fpm

echo "Maintenance completed successfully!"
EOF

chmod +x maintenance.sh
```

### Update Strategy

1. **Staging environment**: Always test updates in a staging environment first
2. **Blue-green deployment**: Use EB's blue-green deployment for zero-downtime updates
3. **Database migrations**: Plan and test database schema changes carefully
4. **Rollback plan**: Always have a rollback strategy ready

This comprehensive guide provides a production-ready LAMP stack deployment on AWS Elastic Beanstalk with enterprise-grade features including high availability, auto-scaling, monitoring, security hardening, cost optimization, and disaster recovery capabilities.
