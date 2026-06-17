import * as cdk from "aws-cdk-lib";
import * as iam from "aws-cdk-lib/aws-iam";
import { Construct } from "constructs";

// ---------------------------------------------------------------------------
// User roster — mirrors the CloudFormation template and Terraform locals
// ---------------------------------------------------------------------------
interface UserRecord {
  username: string;
  name: string;
  title: string;
  email: string;
  team: string;
  group: string; // logical group key
}

const USERS: UserRecord[] = [
  // Stravaco_Admin_Group
  {
    username: "acook",
    name: "Alex Cook",
    title: "Chief Architect",
    email: "acook@stravaco.biz",
    team: "IT",
    group: "admin",
  },
  // Ops_Group
  {
    username: "sbrahamian",
    name: "Sidhar Brahamian",
    title: "Devops Lead",
    email: "sbrahamian@stravaco.biz",
    team: "Operations",
    group: "ops",
  },
  {
    username: "bstichler",
    name: "Bert Stichler",
    title: "AWS Admin",
    email: "bstichler@stravaco.biz",
    team: "Operations",
    group: "ops",
  },
  // Developer_Group
  {
    username: "ralhamein",
    name: "Rasheed Alhamein",
    title: "Development Manager",
    email: "ralhamein@stravaco.biz",
    team: "Developer",
    group: "developer",
  },
  {
    username: "lmckeown",
    name: "Liam Mckeown",
    title: "Developer",
    email: "lmckeown@stravaco.biz",
    team: "Developer",
    group: "developer",
  },
  {
    username: "abrackett",
    name: "Angela Brackett",
    title: "Jr. Developer",
    email: "abrackett@stravaco.biz",
    team: "Developer",
    group: "developer",
  },
  {
    username: "spalamadu",
    name: "Suri Palamadu",
    title: "Senior Developer",
    email: "spalamadu@stravaco.biz",
    team: "Developer",
    group: "developer",
  },
  // Finance_Group
  {
    username: "gmcevoy",
    name: "Gordon McEvoy",
    title: "Finance Manager",
    email: "gmcevoy@stravaco.biz",
    team: "Finance",
    group: "finance",
  },
  // Data_Group
  {
    username: "asingh",
    name: "Anupam Singh",
    title: "Data Engineer",
    email: "asingh@stravaco.biz",
    team: "Data Analyst",
    group: "data",
  },
  {
    username: "bdoans",
    name: "Bethany Doans",
    title: "Jr. Data Analyst",
    email: "bdoans@stravaco.biz",
    team: "Data Analyst",
    group: "data",
  },
  {
    username: "fkhuri",
    name: "Farahd Khuri",
    title: "Data Engineer",
    email: "fkhuri@stravaco.biz",
    team: "Data Analyst",
    group: "data",
  },
];

// ---------------------------------------------------------------------------
// Stack props — environment tag defaults to "Development"
// ---------------------------------------------------------------------------
export interface StravacoIamStackProps extends cdk.StackProps {
  environmentTag?: "Development" | "Production";
}

// ---------------------------------------------------------------------------
// Stack
// ---------------------------------------------------------------------------
export class StravacoIamStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: StravacoIamStackProps = {}) {
    super(scope, id, props);

    const envTag = props.environmentTag ?? "Development";

    // -----------------------------------------------------------------------
    // 1. IAM GROUPS
    // -----------------------------------------------------------------------

    // Developer_Group
    const developerGroup = new iam.Group(this, "DeveloperGroup", {
      groupName: "Developer_Group",
    });
    developerGroup.addManagedPolicy(
      iam.ManagedPolicy.fromAwsManagedPolicyName("AmazonEC2FullAccess")
    );
    developerGroup.addManagedPolicy(
      iam.ManagedPolicy.fromAwsManagedPolicyName("AmazonS3ReadOnlyAccess")
    );
    developerGroup.addManagedPolicy(
      iam.ManagedPolicy.fromAwsManagedPolicyName("CloudWatchEventsFullAccess")
    );

    // Ops_Group
    const opsGroup = new iam.Group(this, "OpsGroup", {
      groupName: "Ops_Group",
    });
    opsGroup.addManagedPolicy(
      iam.ManagedPolicy.fromAwsManagedPolicyName("AmazonEC2FullAccess")
    );
    opsGroup.addManagedPolicy(
      iam.ManagedPolicy.fromAwsManagedPolicyName("CloudWatchEventsFullAccess")
    );
    opsGroup.addManagedPolicy(
      iam.ManagedPolicy.fromAwsManagedPolicyName("AmazonSSMFullAccess")
    );
    opsGroup.addManagedPolicy(
      iam.ManagedPolicy.fromAwsManagedPolicyName("AmazonRDSFullAccess")
    );

    // Finance_Group
    const financeGroup = new iam.Group(this, "FinanceGroup", {
      groupName: "Finance_Group",
    });
    financeGroup.addManagedPolicy(
      iam.ManagedPolicy.fromAwsManagedPolicyName("job-function/Billing")
    );
    financeGroup.addManagedPolicy(
      iam.ManagedPolicy.fromAwsManagedPolicyName("ReadOnlyAccess")
    );

    // Data_Group
    const dataGroup = new iam.Group(this, "DataGroup", {
      groupName: "Data_Group",
    });
    dataGroup.addManagedPolicy(
      iam.ManagedPolicy.fromAwsManagedPolicyName("AmazonS3ReadOnlyAccess")
    );
    dataGroup.addManagedPolicy(
      iam.ManagedPolicy.fromAwsManagedPolicyName("AmazonRDSReadOnlyAccess")
    );

    // Stravaco_Admin_Group
    const adminGroup = new iam.Group(this, "StavacoAdminGroup", {
      groupName: "Stravaco_Admin_Group",
    });
    adminGroup.addManagedPolicy(
      iam.ManagedPolicy.fromAwsManagedPolicyName("AdministratorAccess")
    );
    adminGroup.addManagedPolicy(
      iam.ManagedPolicy.fromAwsManagedPolicyName("AmazonS3FullAccess")
    );
    adminGroup.addManagedPolicy(
      iam.ManagedPolicy.fromAwsManagedPolicyName(
        "AWSBillingConductorFullAccess"
      )
    );
    adminGroup.addManagedPolicy(
      iam.ManagedPolicy.fromAwsManagedPolicyName("job-function/Billing")
    );
    adminGroup.addManagedPolicy(
      iam.ManagedPolicy.fromAwsManagedPolicyName("IAMUserChangePassword")
    );

    // -----------------------------------------------------------------------
    // 2. DEVELOPER GROUP — inline production deny policy
    // -----------------------------------------------------------------------
    const ec2DestructiveActions = [
      "ec2:TerminateInstances",
      "ec2:StopInstances",
      "ec2:RebootInstances",
      "ec2:DeleteVolume",
      "ec2:DeleteSnapshot",
      "ec2:DeleteSecurityGroup",
      "ec2:DeleteSubnet",
      "ec2:DeleteVpc",
      "ec2:DeleteInternetGateway",
      "ec2:DeleteRouteTable",
      "ec2:DeleteRoute",
      "ec2:DeleteNetworkAcl",
      "ec2:DeleteKeyPair",
      "ec2:DeleteLaunchTemplate",
    ];

    const s3DestructiveActions = [
      "s3:DeleteObject",
      "s3:DeleteObjectVersion",
      "s3:DeleteBucket",
      "s3:DeleteBucketPolicy",
      "s3:DeleteBucketWebsite",
      "s3:PutBucketPolicy",
      "s3:PutLifecycleConfiguration",
    ];

    developerGroup.addToPolicy(
      new iam.PolicyStatement({
        sid: "DenyEC2DestructiveOnProduction",
        effect: iam.Effect.DENY,
        actions: ec2DestructiveActions,
        resources: ["*"],
        conditions: {
          StringEquals: { "aws:ResourceTag/Environment": "Production" },
        },
      })
    );

    developerGroup.addToPolicy(
      new iam.PolicyStatement({
        sid: "DenyS3DestructiveOnProduction",
        effect: iam.Effect.DENY,
        actions: s3DestructiveActions,
        resources: ["*"],
        conditions: {
          StringEquals: { "aws:ResourceTag/Environment": "Production" },
        },
      })
    );

    developerGroup.addToPolicy(
      new iam.PolicyStatement({
        sid: "AllowEC2DestructiveOnDevelopment",
        effect: iam.Effect.ALLOW,
        actions: ec2DestructiveActions,
        resources: ["*"],
        conditions: {
          StringEquals: { "aws:ResourceTag/Environment": "Development" },
        },
      })
    );

    developerGroup.addToPolicy(
      new iam.PolicyStatement({
        sid: "AllowS3DestructiveOnDevelopment",
        effect: iam.Effect.ALLOW,
        actions: s3DestructiveActions,
        resources: ["*"],
        conditions: {
          StringEquals: { "aws:ResourceTag/Environment": "Development" },
        },
      })
    );

    // -----------------------------------------------------------------------
    // 3. GROUP LOOKUP MAP
    // -----------------------------------------------------------------------
    const groupMap: Record<string, iam.Group> = {
      admin: adminGroup,
      ops: opsGroup,
      developer: developerGroup,
      finance: financeGroup,
      data: dataGroup,
    };

    // -----------------------------------------------------------------------
    // 4. IAM USERS
    // -----------------------------------------------------------------------
    for (const u of USERS) {
      const user = new iam.User(this, `User-${u.username}`, {
        userName: u.username,
        path: "/",
        groups: [groupMap[u.group]],
      });

      cdk.Tags.of(user).add("Name", u.name);
      cdk.Tags.of(user).add("Title", u.title);
      cdk.Tags.of(user).add("Email", u.email);
      cdk.Tags.of(user).add("Team", u.team);
      cdk.Tags.of(user).add("Environment", envTag);
    }

    // -----------------------------------------------------------------------
    // 5. OUTPUTS
    // -----------------------------------------------------------------------
    new cdk.CfnOutput(this, "DeveloperGroupArn", {
      value: developerGroup.groupArn,
      exportName: `${this.stackName}-DeveloperGroupArn`,
    });
    new cdk.CfnOutput(this, "OpsGroupArn", {
      value: opsGroup.groupArn,
      exportName: `${this.stackName}-OpsGroupArn`,
    });
    new cdk.CfnOutput(this, "FinanceGroupArn", {
      value: financeGroup.groupArn,
      exportName: `${this.stackName}-FinanceGroupArn`,
    });
    new cdk.CfnOutput(this, "DataGroupArn", {
      value: dataGroup.groupArn,
      exportName: `${this.stackName}-DataGroupArn`,
    });
    new cdk.CfnOutput(this, "StavacoAdminGroupArn", {
      value: adminGroup.groupArn,
      exportName: `${this.stackName}-StavacoAdminGroupArn`,
    });
  }
}
