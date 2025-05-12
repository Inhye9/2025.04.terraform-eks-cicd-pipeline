# resource "aws_lambda_function" "aim_lambda" {
#   function_name = "${var.project_name}-exec-lmb"
#   role          = aws_iam_role.lambda_role.arn
#   handler       = "index.handler"
#   runtime       = "python3.11"

# #   filename      = "lambda_function.zip"

# #   source_code_hash = filebase64sha256("lambda_function.zip")

# #   environment {
# #     variables = {
# #       DYNAMODB_TABLE = aws_dynamodb_table.aim_table.name
# #     }
# #   }

#   vpc_config {
#     subnet_ids         = [aws_subnet.aim_private_subnet_a.id, aws_subnet.aim_private_subnet_b.id]
#     security_group_ids = [aws_security_group.aim_lambda_sg.id]
#   }

#   tags = {
#     Name = "aim-lambda-function"
#   }
# }

# resource "aws_security_group" "aim_lambda_sg" {
#   vpc_id = aws_vpc.aim_vpc.id

#   ingress {
#     from_port   = 0
#     to_port     = 65535
#     protocol    = "tcp"
#     cidr_blocks = ["10.0.0.0/16"]
#   }

#   egress {
#     from_port   = 0
#     to_port     = 0
#     protocol    = "-1"
#     cidr_blocks = ["0.0.0.0/0"]
#   }

#   tags = {
#     Name = "aim-lambda-sg"
#   }
# }