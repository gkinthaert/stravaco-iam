#!/usr/bin/env node
import "source-map-support/register";
import * as cdk from "aws-cdk-lib";
import { StravacoIamStack } from "../lib/stravaco-iam-cdk-stack";

const app = new cdk.App();

// Pass environmentTag: "Production" to deploy against prod-tagged resources
new StravacoIamStack(app, "StravacoIamStack", {
  environmentTag: "Development", // change to "Production" when deploying to prod account
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION ?? "us-east-2",
  },
});
