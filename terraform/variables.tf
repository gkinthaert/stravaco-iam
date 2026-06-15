variable "environment" {
  description = "Deployment environment tag"
  type        = string
  default     = "Development"

  validation {
    condition     = contains(["Development", "Production"], var.environment)
    error_message = "Environment must be Development or Production."
  }
}