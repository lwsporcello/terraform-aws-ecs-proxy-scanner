locals {
  vpc_id              = var.use_existing_network ? var.vpc_id : aws_vpc.lacework_vpc[0].id
  internet_gateway_id = var.use_existing_network ? data.aws_internet_gateway.selected[0].id : aws_internet_gateway.lacework_igw[0].id
  sources_cidr        = ["0.0.0.0/0"]

  execution_role_arn = var.use_existing_execution_role ? var.execution_role_arn : aws_iam_role.ecs_execution_role[0].arn
  task_role_arn      = var.use_existing_task_role ? var.task_role_arn : aws_iam_role.ecs_task_role[0].arn
  lb-certificate     = var.use_existing_cert ? (var.use_existing_acm_cert ? var.certificate_arn : aws_acm_certificate.cert[0]) : aws_acm_certificate.cert[0]

  subnets = var.use_existing_network ? data.aws_subnets.vpc_subnets.ids : [aws_subnet.lacework_subnet_1[0].id, aws_subnet.lacework_subnet_2[0].id]

  #proxy scanner configuration formatting
  config = yamlencode({
    static_cache_location : var.static_cache_location
    scan_public_registries : var.scan_public_registries
    lacework : {
      account_name : var.lacework_account_name
      integration_access_token : var.proxy_scanner_token
    },
    registries : var.registries
  })
}

#data
data "aws_vpc" "vpc" {
  id = local.vpc_id
}

data "aws_subnets" "vpc_subnets" {
  filter {
    name   = "vpc-id"
    values = [local.vpc_id]
  }
}

data "aws_availability_zones" "available" {
}

data "aws_region" "current" {}

data "aws_internet_gateway" "selected" {
  count = var.use_existing_network ? 1 : 0

  filter {
    name   = "attachment.vpc-id"
    values = [local.vpc_id]
  }
}

#iam
resource "aws_iam_role" "ecs_execution_role" {
  count                = var.use_existing_execution_role ? 0 : 1
  name                 = "${var.app_name}-task-execution-role"
  max_session_duration = 3600
  path                 = "/"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      },
    ]
  })

  inline_policy {
    name = "AllowCloudWatch"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Sid      = "AllowLoggingToCloudWatch"
          Action   = ["logs:PutLogEvents", "logs:CreateLogStream", "logs:CreateLogGroup"]
          Effect   = "Allow"
          Resource = "arn:aws:logs:*:*:log-group:/ecs/${var.app_name}-*"
        },
      ]
    })
  }

  tags = {
    Name = var.app_name
  }
}

resource "aws_iam_role" "ecs_task_role" {
  count                = var.use_existing_task_role ? 0 : 1
  name                 = "${var.app_name}-task-role"
  max_session_duration = 43200
  path                 = "/"
  #managed_policy_arns  = [aws_iam_policy.agentless_scan_task_policy[0].arn]
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      },
    ]
  })

  tags = {
    Name = var.app_name
  }
}

#networking
resource "aws_vpc" "lacework_vpc" {
  count                = var.use_existing_network ? 0 : 1
  cidr_block           = var.vpc_cidr_block
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = var.app_name
  }
}

resource "aws_route_table" "lacework_rt" {
  count  = var.use_existing_network ? 0 : 1
  vpc_id = local.vpc_id

  tags = {
    Name = "${var.app_name}-rt"
  }
}

resource "aws_route_table_association" "lacework_rt_assoc_1" {
  count          = var.use_existing_network ? 0 : 1
  subnet_id      = aws_subnet.lacework_subnet_1[0].id
  route_table_id = aws_route_table.lacework_rt[0].id
}

resource "aws_route_table_association" "lacework_rt_assoc_2" {
  count          = var.use_existing_network ? 0 : 1
  subnet_id      = aws_subnet.lacework_subnet_2[0].id
  route_table_id = aws_route_table.lacework_rt[0].id
}

resource "aws_internet_gateway" "lacework_igw" {
  count  = var.use_existing_network ? 0 : 1
  vpc_id = local.vpc_id

  tags = {
    Name = "${var.app_name}-igw"
  }
}

resource "aws_route" "lacework_route" {
  count                  = var.use_existing_network ? 0 : 1
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = local.internet_gateway_id
  route_table_id         = aws_route_table.lacework_rt[0].id
}

resource "aws_subnet" "lacework_subnet_1" {
  count                   = var.use_existing_network ? 0 : 1
  vpc_id                  = local.vpc_id
  cidr_block              = var.subnet_cidr_block_1
  availability_zone       = var.az_1
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.app_name}-subnet-1"
  }
}

resource "aws_subnet" "lacework_subnet_2" {
  count                   = var.use_existing_network ? 0 : 1
  vpc_id                  = local.vpc_id
  cidr_block              = var.subnet_cidr_block_2
  availability_zone       = var.az_2
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.app_name}-subnet-2"
  }
}

#efs
resource "aws_efs_file_system" "lacework-proxy-scanner-efs" {
  creation_token = var.app_name
  encrypted      = true

  tags = {
    Name = var.app_name
  }
}

resource "aws_efs_mount_target" "lacework-proxy-scanner-efs-mount" {
  count           = length(local.subnets)
  file_system_id  = aws_efs_file_system.lacework-proxy-scanner-efs.id
  security_groups = [aws_security_group.lacework-proxy-scanner-efs-security-group.id]
  subnet_id       = element(local.subnets, count.index)
}

resource "aws_efs_access_point" "lacework-efs-ap-cache" {
  file_system_id = aws_efs_file_system.lacework-proxy-scanner-efs.id

  root_directory {
    path = "/opt/lacework/cache"
    creation_info {
      owner_gid   = 1000
      owner_uid   = 1000
      permissions = 755
    }
  }
}

#security groups
resource "aws_security_group" "lacework-proxy-scanner-ecs-security-group" {
  name        = "${var.app_name}-ecs-sg"
  description = "${var.app_name} ECS Security Group - allow inbound and outbound for ECS task"
  vpc_id      = local.vpc_id

  ingress {
    protocol        = "tcp"
    from_port       = var.app_port
    to_port         = var.app_port
    security_groups = [aws_security_group.lacework-proxy-scanner-lb-security-group.id]
  }

  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.app_name}-ecs-sg"
  }
}

resource "aws_security_group" "lacework-proxy-scanner-lb-security-group" {
  name        = "${var.app_name}-lb-sg"
  description = "${var.app_name} ECS Security Group - allow inbound for load balancer"
  vpc_id      = local.vpc_id

  ingress {
    protocol    = "tcp"
    from_port   = var.lb_port
    to_port     = var.lb_port
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.app_name}-lb-sg"
  }
}

resource "aws_security_group" "lacework-proxy-scanner-efs-security-group" {
  name        = "${var.app_name}-efs-sg"
  description = "${var.app_name} EFS Security Group - allow ECS to EFS"
  vpc_id      = local.vpc_id

  ingress {
    #security_groups = [aws_security_group.lacework-proxy-scanner-ecs-security-group.id]
    cidr_blocks = ["0.0.0.0/0"]
    protocol    = "tcp"
    from_port   = 2049
    to_port     = 2049
  }

  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
    #security_groups = [aws_security_group.lacework-proxy-scanner-ecs-security-group.id]
  }

  tags = {
    Name = "${var.app_name}-efs-sg"
  }
}

#ecs
resource "aws_ecs_task_definition" "lacework-proxy-scanner-ecs-task-definition" {
  family                   = "${var.app_name}-task-definition"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.cpu
  memory                   = var.mem

  container_definitions = jsonencode([
    {
      name      = var.app_name
      image     = "${var.image_name}:${var.image_tag}"
      cpu       = 1024
      memory    = 1024
      essential = true

      portMappings = [
        {
          containerPort = var.app_port
          hostPort      = var.app_port
        }
      ]

      mountPoints = [
        {
          sourceVolume  = "cache"
          containerPath = "/opt/lacework/cache"
          readOnly      = false
        }
      ]

      environment = [
        {
          name  = "LW_CONFIG"
          value = base64encode(local.config)
        },
        {
          name  = "LOG_LEVEL"
          value = var.log_level
        }
      ]

      command = ["sh", "-c", "echo $LW_CONFIG | base64 -d >/opt/lacework/config/config.yml && sh /opt/lacework/run.sh"]

      heatlhCheck = {
        command     = ["wget --no-verbose --tries=1 --spider http://localhost:8080/v1/notification?registry_name="]
        interval    = 5
        timeout     = 5
        retries     = 3
        startPeriod = 300
      }

      logConfiguration = var.enable_logging ? {
        logDriver = "awslogs"
        options = {
          awslogs-group         = "/ecs/${var.app_name}-logs"
          awslogs-region        = "${data.aws_region.current.name}"
          awslogs-create-group  = "true"
          awslogs-stream-prefix = "ecs"
        }
      } : null
    }
  ])

  execution_role_arn = local.execution_role_arn
  task_role_arn      = local.task_role_arn

  volume {
    name = "cache"
    efs_volume_configuration {
      file_system_id     = aws_efs_file_system.lacework-proxy-scanner-efs.id
      transit_encryption = "ENABLED"
      authorization_config {
        access_point_id = aws_efs_access_point.lacework-efs-ap-cache.id
        iam             = "DISABLED"
      }
    }
  }

  tags = {
    Name = var.app_name
  }
}

resource "aws_ecs_cluster" "lacework-proxy-scanner-ecs-cluster" {
  name = var.app_name

  tags = {
    Name = var.app_name
  }
}

resource "aws_ecs_service" "lacework-proxy-scanner-ecs-service" {
  name                   = "${var.app_name}-service"
  cluster                = aws_ecs_cluster.lacework-proxy-scanner-ecs-cluster.id
  desired_count          = var.min_count
  force_new_deployment   = var.force_new_deployment
  enable_execute_command = true
  launch_type            = "FARGATE"
  propagate_tags         = "SERVICE"
  task_definition        = aws_ecs_task_definition.lacework-proxy-scanner-ecs-task-definition.arn

  load_balancer {
    target_group_arn = aws_lb_target_group.lacework-proxy-scanner-lb-tg.arn
    container_name   = var.app_name
    container_port   = var.app_port
  }

  network_configuration {
    subnets          = local.subnets
    assign_public_ip = true
    security_groups  = [aws_security_group.lacework-proxy-scanner-ecs-security-group.id, aws_security_group.lacework-proxy-scanner-lb-security-group.id, aws_security_group.lacework-proxy-scanner-efs-security-group.id]
  }

  tags = {
    Name = var.app_name
  }
}

#certificate management
resource "aws_acm_certificate" "cert" {
  count             = var.use_existing_acm_cert ? 0 : 1
  private_key       = var.use_existing_cert ? file(var.private_key) : tls_private_key.proxy-scanner[0].private_key_pem
  certificate_body  = var.use_existing_cert ? file(var.certificate) : tls_locally_signed_cert.proxy-scanner[0].cert_pem
  certificate_chain = var.use_existing_cert ? file(var.issuer) : tls_self_signed_cert.ca[0].cert_pem
  depends_on        = [tls_locally_signed_cert.proxy-scanner]

  tags = {
    Name = var.app_name
  }
}

#load balancer
resource "aws_lb" "lacework-proxy-scanner-lb" {
  name               = var.app_name
  internal           = true
  load_balancer_type = "application"
  idle_timeout       = 300
  security_groups    = [aws_security_group.lacework-proxy-scanner-lb-security-group.id]

  dynamic "subnet_mapping" {
    for_each = local.subnets
    content {
      subnet_id = local.subnets[subnet_mapping.key]
    }
  }

  tags = {
    Name = var.app_name
  }
}

resource "aws_lb_target_group" "lacework-proxy-scanner-lb-tg" {
  name        = var.app_name
  vpc_id      = local.vpc_id
  port        = var.app_port
  protocol    = "HTTP"
  target_type = "ip"

  health_check {
    matcher = "404"
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = var.app_name
  }
}

resource "aws_lb_listener" "lacework-proxy-scanner-lb-listener" {
  load_balancer_arn = aws_lb.lacework-proxy-scanner-lb.arn
  port              = var.lb_port
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = local.lb-certificate.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.lacework-proxy-scanner-lb-tg.arn
  }

  tags = {
    Name = var.app_name
  }
}

#autoscaling
resource "aws_appautoscaling_target" "lacework-proxy-scanner-as-target" {
  min_capacity       = var.min_count
  max_capacity       = var.max_count
  resource_id        = "service/${aws_ecs_cluster.lacework-proxy-scanner-ecs-cluster.name}/${aws_ecs_service.lacework-proxy-scanner-ecs-service.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"

  tags = {
    Name = var.app_name
  }
}

resource "aws_appautoscaling_policy" "lacework-proxy-scanner-as-policy-memory" {
  name               = "memory-autoscaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.lacework-proxy-scanner-as-target.resource_id
  scalable_dimension = aws_appautoscaling_target.lacework-proxy-scanner-as-target.scalable_dimension
  service_namespace  = aws_appautoscaling_target.lacework-proxy-scanner-as-target.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageMemoryUtilization"
    }

    target_value = var.mem_threshold
  }
}

resource "aws_appautoscaling_policy" "lacework-proxy-scanner-as-policy-cpu" {
  name               = "cpu-autoscaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.lacework-proxy-scanner-as-target.resource_id
  scalable_dimension = aws_appautoscaling_target.lacework-proxy-scanner-as-target.scalable_dimension
  service_namespace  = aws_appautoscaling_target.lacework-proxy-scanner-as-target.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }

    target_value = var.cpu_threshold
  }
}

#logging
resource "aws_cloudwatch_log_group" "log-group" {
  count             = var.enable_logging ? 1 : 0
  name              = "/ecs/${var.app_name}-logs"
  retention_in_days = 14
  tags = {
    Name = var.app_name
  }
}
