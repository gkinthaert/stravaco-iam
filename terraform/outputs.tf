output "developer_group_arn" {
  value = aws_iam_group.developer.arn
}

output "ops_group_arn" {
  value = aws_iam_group.ops.arn
}