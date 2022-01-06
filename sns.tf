resource "aws_sns_topic" "user_updates" {
  name = "user-updates-topic"
}

resource "aws_sns_topic_subscription" "lambda" {
  topic_arn = aws_sns_topic.user_updates.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.func.arn
}



#CodeDeployEC2ServiceRole_sns attachment
resource "aws_iam_role_policy_attachment" "CodeDeployEC2ServiceRole_snsPolicy" {
  role       = aws_iam_role.CodeDeployEC2ServiceRole.name
  policy_arn = aws_iam_policy.SNSPolicy.arn
}

resource "aws_iam_policy" "SNSPolicy" {
  name = "SNSPolicy"

  policy = jsonencode(
    {
      "Version" : "2012-10-17"
      "Statement" : [
        {
          "Action" : [
            "sns:Create*",
            "sns:Delete*",
            "sns:Get*",
            "sns:List*",
            "sns:Publish",
            "sns:Set*"
          ],
          "Effect" : "Allow",
          "Resource" : "arn:aws:sns:${var.REGION}:${var.AWSaccountID}:*"
                        

        },
      ]
    }
  )
}


