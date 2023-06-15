locals {
  vpc_id             = var.use_existing_vpc ? var.vpc_id : aws_vpc.lacework_vpc[0].id
  subnet_id          = var.use_existing_subnet ? var.subnet_id : aws_subnet.lacework_subnet[0].id
  execution_role_arn = var.use_existing_execution_role ? var.execution_role_arn : aws_iam_role.ecs_execution_role[0].id
  task_role_arn      = var.use_existing_task_role ? var.task_role_arn : aws_iam_role.ecs_task_role[0].id
  sources_cidr = ["0.0.0.0/0"]

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

#proxy scanner config load
#data "local_file" "config_yaml" {
#  filename = "${path.module}/config.yaml"
#}

#iam
resource "aws_iam_role" "ecs_execution_role" {
  count                = var.use_existing_execution_role ? 0 : 1
  name                 = "${var.app_name}-task-execution-role"
  max_session_duration = 3600
  path                 = "/"
  #managed_policy_arns  = ["arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"]
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

#resource "aws_iam_role_policy_attachment" "ecs-task-execution-role-policy-attachment" {
#  role       = aws_iam_role.ecs_task_execution_role.name
#  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
#}

#resource "aws_iam_role_policy_attachment" "task_s3" {
#  role       = "${aws_iam_role.ecs_task_role.name}"
#  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
#}

#networking
resource "aws_vpc" "lacework_vpc" {
  count                = var.use_existing_vpc ? 0 : 1
  cidr_block           = var.vpc_cidr_block
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = var.app_name
  }
}

resource "aws_internet_gateway" "lacework_gw" {
  count  = var.use_existing_vpc ? 0 : 1
  vpc_id = local.vpc_id

  tags = {
    Name = var.app_name
  }
}

resource "aws_route_table" "lacework_rt" {
  count  = var.use_existing_subnet ? 0 : 1
  vpc_id = local.vpc_id

  tags = {
    Name = var.app_name
  }
}

resource "aws_subnet" "lacework_subnet" {
  count      = var.use_existing_subnet ? 0 : 1
  vpc_id     = local.vpc_id
  cidr_block = var.vpc_cidr_block

  tags = {
    Name = "main"
  }
}

data "aws_subnets" "vpc_subnets" {
  filter {
    name   = "vpc-id"
    values = [local.vpc_id]
  }
}

data "aws_availability_zones" "available" {
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
  count          = length(data.aws_availability_zones.available.names)
  file_system_id = aws_efs_file_system.lacework-proxy-scanner-efs.id
  #subnet_id      = data.aws_subnet.vpc_subnet[count.index].arn
  subnet_id = element(data.aws_subnets.vpc_subnets.ids, count.index)
  #security_groups = [aws_security_group.efs.id]
}

#security groups
#resource "aws_security_group" "lacework-proxy-scanner-ecs-security-group" {
#  name        = var.app_name
#  description = "${var.app_name} ECS Security Group"
#  vpc_id      = local.vpc_id
#  ingress {
#    protocol    = "tcp"
#    from_port   = local.port
#    to_port     = local.port
#    cidr_blocks = [data.aws_vpc.vpc.cidr_block]
#  }
#  egress {
#    protocol    = "-1"
#    from_port   = 0
#    to_port     = 0
#    cidr_blocks = ["0.0.0.0/0"]
#  }
#  tags = {
#    Name = var.app_name
#  }
#}

#ecs
resource "aws_ecs_task_definition" "lacework-proxy-scanner-ecs-task-definition" {
  family = "service"
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
          containerPath = "/opt/lacework"
          readOnly      = false
        },
        {
          sourceVolume  = "config"
          containerPath = "/opt/lacework/config"
          readOnly      = true
        }
      ]
      #environment = [
      #  {
      #    LW_CONFIG = base64encode(templatefile("${path.module}/config.yaml", {}))
      #  }
      #]
      #command = ["sh", "-c", "echo $LW_CONFIG | base64 --decode >/opt/lacework/config/config.yml && /opt/lacework/run.sh"]
    }
  ])

  execution_role_arn = local.execution_role_arn
  task_role_arn      = local.task_role_arn

  volume {
    name = "config"
    efs_volume_configuration {
      file_system_id     = aws_efs_file_system.lacework-proxy-scanner-efs.id
      root_directory     = "/opt/lacework/config"
      transit_encryption = "ENABLED"
    }
  }

  volume {
    name = "cache"
    efs_volume_configuration {
      file_system_id     = aws_efs_file_system.lacework-proxy-scanner-efs.id
      root_directory     = "/opt/lacework"
      transit_encryption = "ENABLED"
    }
  }

  provisioner "file" {
    content     = local.config
    destination = "/opt/lacework/config/config.yaml"
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
  desired_count          = var.task_count
  force_new_deployment   = var.force_new_deployment
  enable_execute_command = true
  launch_type            = "FARGATE"
  propagate_tags         = "SERVICE"
  task_definition        = aws_ecs_task_definition.lacework-proxy-scanner-ecs-task-definition.arn
}

#load balancer
resource "aws_lb" "lacework-proxy-scanner-lb" {
  name               = var.app_name
  internal           = true
  load_balancer_type = "application"
  idle_timeout       = 300
  security_groups    = []
  subnets            = data.aws_subnets.vpc_subnets.ids
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

}

resource "aws_lb_listener" "lacework-proxy-scanner-lb-listener" {
  load_balancer_arn = aws_lb.lacework-proxy-scanner-lb.arn
  port              = var.lb_port
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = ""

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.lacework-proxy-scanner-lb-tg.arn
  }
}
