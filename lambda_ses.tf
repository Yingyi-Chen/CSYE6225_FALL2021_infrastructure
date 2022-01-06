resource "aws_lambda_permission" "with_sns" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.func.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.user_updates.arn
}

resource "aws_lambda_function" "func" {
  s3_bucket = "lambda.${var.PROFILE}.yingyi.me"
  s3_key = "exports.zip"
  function_name = "lambda_called_from_sns"
  role          = aws_iam_role.lambdaRole.arn
  handler       = "exports.handler"
  runtime       = "nodejs14.x"
}

resource "aws_iam_role" "lambdaRole" {
  name = "iam_for_lambda_with_sns"

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      },
    ]
  })
}

resource "aws_iam_policy" "SESPolicy" {
  name = "SESPolicy"

  policy = jsonencode(
    {
      "Version" : "2012-10-17"
      "Statement" : [
        {
          "Action" : [
            "ses:Send*",
            "ses:Create*",
            "ses:List*",
            "ses:Put*",
            "ses:Set*",
            "ses:Update*",
            "ses:Verify*"
          ],
          "Effect" : "Allow",
          "Resource" : ["arn:aws:ses:${var.REGION}:${var.AWSaccountID}:identity/${var.PROFILE}.yingyi.me}/*",
                        "arn:aws:ses:${var.REGION}:${var.AWSaccountID}:identity/${var.PROFILE}.yingyi.me"]

        },
      ]
    }
  )
}

resource "aws_iam_policy" "DynamoDB_for_lambda_Policy" {
  name = "DynamoDB_for_lambda_Policy"

  policy = jsonencode(
    {
      "Version" : "2012-10-17"
      "Statement" : [
        {
          "Action" : [
            "dynamodb:List*",
            "dynamodb:DescribeLimits",
            "dynamodb:BatchGet*",
            "dynamodb:DescribeStream",
            "dynamodb:DescribeTable",
            "dynamodb:DescribeTimeToLive",
            "dynamodb:Get*",
            "dynamodb:Query",
            "dynamodb:Scan",
            "dynamodb:BatchWrite*",
            "dynamodb:CreateTable",
            "dynamodb:Delete*",
            "dynamodb:Update*",
            "dynamodb:PutItem"
          ],
          "Effect" : "Allow",
          "Resource" : ["arn:aws:dynamodb:${var.REGION}:${var.AWSaccountID}:table/${var.tableName}/*",
                        "arn:aws:dynamodb:${var.REGION}:${var.AWSaccountID}:table/${var.tableName}"]
        }
      ]
    }
  )
}

resource "aws_iam_role_policy_attachment" "lambdaRole_SESPolicyAttach" {
  role       = aws_iam_role.lambdaRole.name
  policy_arn = aws_iam_policy.SESPolicy.arn
}

resource "aws_iam_role_policy_attachment" "lambda_dynamo_PolicyAttach" {
  role       = aws_iam_role.lambdaRole.name
  policy_arn = aws_iam_policy.DynamoDB_for_lambda_Policy.arn
}