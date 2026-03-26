# EC2 Deployment Instructions

This guide provides steps for deploying the Multi-Agent Framework to an AWS EC2 instance.

## Prerequisites

- AWS Account
- EC2 Instance (t3.medium or larger, Ubuntu 22.04 LTS recommended)
- Domain name pointing to EC2 Elastic IP
- Docker and Docker Compose installed on the EC2 instance

## Step 1: Prepare EC2 Instance

1. **SSH into the EC2 instance**:
   ```bash
   ssh -i your-key.pem ubuntu@your-ec2-public-ip
   ```

2. **Install Docker and Docker Compose**:
   ```bash
   sudo apt update
   sudo apt install -y docker.io docker-compose
   sudo usermod -aG docker ubuntu
   # Re-login for group changes to take effect
   ```

## Step 2: Deploy the Framework

1. **Clone the repository**:
   ```bash
   git clone <repo-url>
   cd trellis-agent-platform
   ```

2. **Run the deployment script**:
   ```bash
   ./deploy/setup-ec2.sh
   ```

## Step 3: Configure SSL with Traefik (Optional)

To enable HTTPS with Let's Encrypt, update `traefik/traefik.yml` and add appropriate Docker labels to services in `docker-compose.yml`.

## Monitoring and Maintenance

- **View Logs**: `docker-compose logs -f`
- **Database Backups**: Use `pg_dump` to create backups of the PostgreSQL volume.
- **Scaling**: For horizontal scaling, consider using AWS ECS or Kubernetes (EKS).
