terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "nexus_static_assets" {
  bucket = "nexus-commerce-assets-prod"
}

resource "aws_cloudfront_distribution" "nexus_cdn" {
  origin {
    domain_name = aws_s3_bucket.nexus_static_assets.bucket_regional_domain_name
    origin_id   = "S3-nexus-assets"
  }
  enabled = true
}

