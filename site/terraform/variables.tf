variable "cloudflare_api_token" {
  description = "Cloudflare API token with DNS edit permission on the vulnes.is zone."
  type        = string
  sensitive   = true
}

variable "cloudflare_zone_id" {
  description = "Cloudflare zone ID for vulnes.is."
  type        = string
  default     = "4066f0b161bc71744adb52fbd584b691"
}

variable "github_pages_target" {
  description = "GitHub Pages CNAME target for the Vulnesis organisation."
  type        = string
  default     = "vulnesis.github.io"
}

variable "manage_pages" {
  description = "Whether Terraform owns the GitHub Pages block. Default false; import the repository before enabling."
  type        = bool
  default     = false
}

variable "github_token" {
  description = "GitHub token for the integrations/github provider. Required only when manage_pages is true."
  type        = string
  sensitive   = true
  default     = ""
}