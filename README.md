# nextcloud-server
[AWS CloudFormation](https://aws.amazon.com/cloudformation/) template that provisions an EC2 instance running [Nextcloud](https://nextcloud.com/) file synchronization and sharing server, with a new [Amazon S3](https://aws.amazon.com/s3/) bucket as primary storage and [AWS Backup](https://aws.amazon.com/s3/) for data protection. Includes option to mount existing S3 bucket.


## Notice
Although this repository is released under the [MIT-0](LICENSE) license, its CloudFormation template uses features from [Nextcloud](https://github.com/nextcloud/server) project. Nextcloud project's licensing includes the [AGPL](https://github.com/nextcloud/server?tab=AGPL-3.0-1-ov-file) license.

The template offers the option to install [Webmin](https://github.com/webmin/webmin) which is released under [BSD-3-Clause](https://github.com/webmin/webmin?tab=BSD-3-Clause-1-ov-file) license. Usage of template indicates acceptance of license agreements of all software that is installed in the EC2 instance. 


## Architecture diagram
<img alt="architecture" src="nextcloud-server.png">


## Deployment from CloudFormation console
Download [UbuntuLinux-Nextcloud.yaml](UbuntuLinux-Nextcloud.yaml) file, and login to AWS [CloudFormation console](https://console.aws.amazon.com/cloudformation/home#/stacks/create/template). 

Start the [Create Stack wizard](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-console-create-stack.html#cfn-using-console-initiating-stack-creation) by choosing **Create Stack**. [Select stack template](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-using-console-create-stack-template.html) by selecting **Upload a template file**, **Choose File**, select your `.yaml` file and click **Next**. Enter a **Stack name** and specify parameters values. 



### Parameter options
EC2 instance
- `ec2Name`: EC2 instance name 
- `ec2KeyPair`: [EC2 key pair](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html) name. [Create key pair](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/create-key-pairs.html) if necessary
- `osVersion`: operating system version and processor architecture. Default architecture is [Graviton](https://aws.amazon.com/ec2/graviton/) arm64
- `instanceType`: EC2 [instance type](https://aws.amazon.com/ec2/instance-types/). Do ensure type matches selected processor architecture. Default is `t4g.xlarge` [burstable instance type](https://aws.amazon.com/ec2/instance-types/t4/)

Network
- `vpcID`: [VPC](https://docs.aws.amazon.com/vpc/latest/userguide/what-is-amazon-vpc.html) with internet connectivity. Select [default VPC](https://docs.aws.amazon.com/vpc/latest/userguide/default-vpc.html) if unsure
- `subnetID`: subnet with internet connectivity. Select subnet in default VPC if unsure
- `displayPublicIP`: select `No` if your EC2 instance will not receive [public IP address](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html#concepts-public-addresses). EC2 private IP will be displayed in CloudFormation Outputs section instead. Default is `Yes`
- `assignStaticIP`: associates a static public IPv4 address using [Elastic IP address](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html). Default is `Yes`

Remote Administration
- `ingressIPv4`: allowed IPv4 source prefix to remote administration services, e.g. `1.2.3.4/32`. You can get your source IP from [https://checkip.amazonaws.com](https://checkip.amazonaws.com). Use `127.0.0.1/32` to block incoming access from public internet. Default is `0.0.0.0/0`. 
- `ingressIPv6`: allowed IPv6 source prefix to remote administration services. Use `::1/128` to block all incoming IPv6 access. Default is `::/0`
- `allowSSHport`: allow inbound SSH. Option does not affect [EC2 Instance Connect](https://aws.amazon.com/blogs/compute/new-using-amazon-ec2-instance-connect-for-ssh-access-to-your-ec2-instances/) access. Default is `No`
- `installDCV`: install graphical desktop environment and [NICE DCV](https://aws.amazon.com/hpc/dcv/) server. Default is `No`
- `installWebmin`: install [Webmin](https://webmin.com/) web-based system administration tool. Default is `No`

SSH, NICE DCV and Webmin inbound access from internet are restricted to `ingressIPv4` and `ingressIPv6` IP prefixes. 

Nextcloud
- `adminUserName`: Nextcloud admin username. Default is `admin`
- `phpVersion`: PHP version to install. Uses [Ondřej Surý](https://deb.sury.org/)'s [ppa:ondrej/php](https://launchpad.net/~ondrej/+archive/ubuntu/php/) repository 
- `databaseOption`: `MariaDB` or `MySQL`. Default is `MariaDB`
- `r53ZoneID` (optional):  [Amazon Route 53](https://aws.amazon.com/route53/) hosted zone ID to grant access for use with Certbot [certbot-dns-route53](#option-2-using-certbot-certbot-dns-route53-plugin) DNS plugin.  A `*` value will grant access to all Route 53 zones in your AWS account. Permission is restricted to **_acme-challenge.\*** TXT DNS records using [resource record set permissions](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-permissions.html). Default is empty string for no access

S3
- `s3StorageClass`: [S3 storage class](https://docs.aws.amazon.com/AmazonS3/latest/userguide/storage-class-intro.html) for primary storage to associate uploaded file with. Default is `STANDARD`
- `enableS3bucketLogging`: enable [S3 server access logging](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-server-access-logging.html). Default is `No`
- `externalS3Bucket` (optional): option to mount existing S3 bucket within Nextcloud as [external storage](https://docs.nextcloud.com/server/latest/admin_manual/configuration_files/external_storage_configuration_gui.html). Specify bucket name in your account
- `externalS3BucketRegion`: [AWS Region](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html#concepts-regions) where `externalS3Bucket` is located


EBS
- `volumeSize`: [Amazon EBS](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AmazonEBS.html) volume size
- `volumeType`: [EBS General Purpose Volume](https://aws.amazon.com/ebs/general-purpose/) type

AWS Backup
- `backupResource`: option to backup EC2 instance, S3 bucket, existing S3 bucket mounted as external storage, or none. [Versioning](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html) must be enabled on S3 bucket mounted as external storage before [AWS Backup](https://docs.aws.amazon.com/AmazonS3/latest/userguide/backup-for-s3.html) can back it up. Default is `EC2-and-S3` 
- `scheduleExpression`: CRON expression specifying when AWS Backup initiates a backup job. Default is `cron(0 1 ? * * *)`
- `scheduleExpressionTimezone`: timezone in which the schedule expression is set. Default is `Etc/UTC`
- `deleteAfterDays`: number of days after creation that a recovery point is deleted. Default is `7` days


It may take more than 30 minutes to provision the entire stack. After your stack has been successfully created, its status changes to **CREATE_COMPLETE**.


### CloudFormation Outputs
The following are available in **Outputs** section 

- `DCVwebConsole` (if `installDCV` is `Yes`): NICE DCV web browser console URL link. Login as user specified in *Description* field. 
- `EC2console`: EC2 console URL link to your EC2 instance
- `EC2instanceConnect`: [EC2 Instance Connect](https://aws.amazon.com/blogs/compute/new-using-amazon-ec2-instance-connect-for-ssh-access-to-your-ec2-instances/) URL link. Functionality is only available under [certain conditions](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-connect-prerequisites.html)
- `NextcloudLogUrl`: Cloudwatch [log group](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html) with the contents of your EC2 instance [nextcloud log](https://docs.nextcloud.com/server/stable/admin_manual/configuration_server/logging_configuration.html)
- `SetPasswordCmd`: command to [set Nextcloud admin password](#nextcloud-admin-user-password)
- `SSMsessionManager` or `SSMsessionManagerDCV`: [SSM Session Manager](https://aws.amazon.com/blogs/aws/new-session-manager/) URL link
- `WebminUrl` (if `installWebmin` is `Yes`): Webmin URL link. Set the root password by running `sudo passwd root` from `EC2instanceConnect`, `SSMsessionManager` or SSH session first
- `WebUrl`: EC2 web server URL link

### Nextcloud admin user password
Use either EC2 instance connect or SSM session manager URL link to obtain in-browser terminal access to your EC2 instance. Copy and paste `SetPasswordCmd` value to set Nextcloud admin password. For example, if `adminUserName` value is `admin`, the command is

```
sudo -u www-data php /var/www/html/occ user:resetpassword admin
```
After which, you can login to your Nextcloud application using `WebUrl` link or proceed to install a HTTPS certificate.


## Obtaining certificate for HTTPS using Certbot 
The EC2 instance uses a self-signed certificate for HTTPS. You can use [Certbot](https://certbot.eff.org/pages/about) to automatically obtain and install [Let's Encrypt](https://letsencrypt.org/) certificate on your web server.

### Prerequisites
Ensure you have a domain name whose DNS entry resolves to your EC2 instance IP address. If you do not have a domain, you can [register a new domain](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/domain-register.html#domain-register-procedure-section) using [Amazon Route 53](https://aws.amazon.com/route53/) and [create a DNS A record](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-creating.html).

### Obtain HTTPS certificate

#### Option 1: Using Certbot Apache plugin
This option requires your domain name to resolve to your EC2 instance *public* IP address. From terminal, run the below command
```
sudo certbot --apache
```

#### Option 2: Using Certbot certbot-dns-route53 plugin
The [certbot-dns-route53](https://certbot-dns-route53.readthedocs.io/en/stable/) option requires your DNS to be hosted by Route 53. It supports wildcard certificates and domain names that resolve to private IP addresses. Ensure that Route 53 zone access is granted by specifying `r53ZoneID` value.  From terminal, run the below command
```
sudo certbot --dns-route53 --installer apache
```

Follow instructions to have Certbot request and install certificate on your web server. Refer to Certbot site for [help](https://certbot.eff.org/pages/help) with this tool.  

### Configure HSTS
To configure [HTTP Strict Transport Security (HSTS)](https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security) headers, edit `*ssl.conf` file in `/etc/apache2/sites-available/` folder and add the following text between `<VirtualHost>` and `</VirtualHost>` rows.

```
    <IfModule mod_headers.c>
      Header always set Strict-Transport-Security "max-age=15552000; includeSubDomains"
    </IfModule>
```
Verify Apache configuration
```
sudo apachetl -t
```

Reload Apache server
```
sudo systemctl reload apache2
```


## Managing and using Nextcloud

### Sending email
Nextcloud supports [email server](https://docs.nextcloud.com/server/latest/admin_manual/configuration_server/email_configuration.html) for password reset and activity notifications. You can configure Nextcloud to use [external SMTP server](https://docs.nextcloud.com/server/latest/admin_manual/configuration_server/email_configuration.html#configuring-an-smtp-server) (e.g. [Amazon SES](https://docs.aws.amazon.com/ses/latest/dg/send-email-smtp.html)), or [sendmail](https://docs.nextcloud.com/server/latest/admin_manual/configuration_server/email_configuration.html#configuring-sendmail-qmail).

When configuring external SMTP server, use 465, 587 or supported port number that is not 25. Amazon EC2 [restricts](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-resource-limits.html#port-25-throttle) email sending using port 25 on all instances by default. You can request that this restriction be removed if you are using port 25 for external SMTP server or sendmail. Refer to [How do I remove the restriction on port 25 from my Amazon EC2 instance or Lambda function?](https://repost.aws/knowledge-center/ec2-port-25-throttle) for more information.

### Using the occ command
The [occ](https://docs.nextcloud.com/server/latest/admin_manual/configuration_server/occ_command.html) command is Nextcloud's command-line interface. It is used to perform common server operations such as installing and upgrading Nextcloud, and must be run as HTTP user, i.e. `sudo -u www-data php /var/www/html/occ`. On the EC2 instance, you can use the alias `nextcloud.occ`.

### Mounting external storage services as external storage
Nextcloud [external storage](https://docs.nextcloud.com/server/latest/admin_manual/configuration_files/external_storage_configuration_gui.html) feature enables you to mount external storage services including Windows file servers and S3 buckets as secondary storage devices. Refer to [NextCloud documentation](https://docs.nextcloud.com/server/latest/admin_manual/configuration_files/external_storage_configuration_gui.html#available-storage-backends) for details.

### Downloads
Desktop and mobile applications download links are available from [Nextcloud Install](https://nextcloud.com/install/#install-clients) page

### Documentation
The CloudFormation template focuses on cloud storage and file sharing features of [Nextcloud Files](https://nextcloud.com/files/). Administration and User manuals are available from Nextcloud [documentation site](https://docs.nextcloud.com/). 

### Further information
Nextcloud is mentioned by the following blog posts
- [Scale your Nextcloud with Storage on Amazon Simple Storage Service (Amazon S3)](https://aws.amazon.com/blogs/opensource/scale-your-nextcloud-with-storage-on-amazon-simple-storage-service-amazon-s3/)
- [Advanced Nextcloud Workflows with Amazon Simple Storage Service (Amazon S3)](https://aws.amazon.com/blogs/opensource/advanced-nextcloud-workflows-with-storage-on-amazon-simple-storage-service-amazon-s3-2/)



## Data protection

### S3 primary storage
Amazon S3 is used to provide almost unlimited, cost-effective and [durable](https://aws.amazon.com/s3/faqs/#Durability_.26_Data_Protection) storage over EBS. Using S3 as [primary storage](https://docs.nextcloud.com/server/latest/admin_manual/configuration_files/primary_storage.html) provides [performance benefits](
https://docs.nextcloud.com/server/latest/admin_manual/configuration_files/primary_storage.html#performance-implications) over S3 as [external storage](https://docs.nextcloud.com/server/latest/admin_manual/configuration_files/external_storage/amazons3.html), including support for [large file uploads](https://docs.nextcloud.com/server/latest/admin_manual/configuration_files/big_file_upload_configuration.html#large-file-upload-on-object-storage).

Note that files are not accessible outside of NextCloud as all metadata (filenames, directory structures, etc) is stored in MariaDB/MySQL database on EC2 instance. The S3 bucket holds the file content by unique identifier and *not* filename. This has implications for [data backup and recovery](https://docs.nextcloud.com/server/latest/admin_manual/configuration_files/primary_storage.html#data-backup-and-recovery-implications), and it is important to backup both EC2 instance and S3 bucket data. 

### Restoring from backup
If you enable AWS Backup, you can restore your [EC2 instance](https://docs.aws.amazon.com/aws-backup/latest/devguide/restoring-ec2.html) and [S3 data](https://docs.aws.amazon.com/aws-backup/latest/devguide/restoring-s3.html) from recovery points (backups) in your [backup vault](https://docs.aws.amazon.com/aws-backup/latest/devguide/vaults.html). The CloudFormation template creates an IAM role that grants AWS Backup permission to restore your backups. Role name can be located in your CoudFormation stack Resources section where Logical ID is `backupRestoreRole`.

### Recovery points protection
To protect recovery points from inadvertent or malicious deletions, you can enable [AWS Backup Vault Lock](https://docs.aws.amazon.com/aws-backup/latest/devguide/vault-lock.html) in compliance mode to provide immutable WORM (write-once, read-many) backups. Vaults that are locked in compliance mode *cannot be deleted* once the cooling-off period ("grace time") expires if any recovery points are in the vault. Refer to [Protecting data with AWS Backup Vault Lock](https://aws.amazon.com/blogs/storage/protecting-data-with-aws-backup-vault-lock/) for more information. 

### Filter IAM policy source IP
Nextcloud server uses [EC2 IAM role](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html) for S3 primary storage access. If `assignStaticIP` is `Yes`, you can limit access to only your Nextcloud server. This ensures that even when the session credentials are stolen, an attacker cannot directly use it to access files from his own address.

The created IAM role can be located in CloudFormation console stack **Resources** section with `Logical ID` of **instanceIamRole**. Click on the `Physical ID` value to edit inline permission in IAM console. Change `aws:SourceIp` value from `0.0.0.0/0` to your EC2 instance public IPv4 address. If IP address is 1.2.3.4, your updated policy may look similar to below

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Condition": {
        "IpAddress": {
          "aws:SourceIp": "1.2.3.4/32"
        }
      },
      "Action": [
        "s3:*"
      ],
      "Resource": [
        "arn:aws:s3:::nextcloud-s3bucket-8ohvkk9vzv2f",
        "arn:aws:s3:::nextcloud-s3bucket-8ohvkk9vzv2f/*"
      ],
      "Effect": "Allow"
    }
  ]
}
```

An [IAM user](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users.html) with attached [policy](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html#inline-policies) is used for S3 external storage access. Using EC2 IAM role for external storage currently generates errors in nextcloud.log. ([Issue #46400](https://github.com/nextcloud/server/issues/46400)) The IAM user can be located in CloudFormation **Resources** section where `Logical ID` is **iamUser**, and you may want to configure the associated policy `aws:SourceIp` value. 

To use its credentials to mount other S3 buckets in your AWS account as [external storage](https://docs.nextcloud.com/server/latest/admin_manual/configuration_files/external_storage/amazons3.html), modify associated IAM policy `Resource` key and add your desired S3 bucket names. The access key and secret can be retrieved by running `sudo grep secret /root/install-nextcloud.sh`.

### Sensitive data protection
To strengthen data security posture, you can enable [Amazon Macie](https://aws.amazon.com/macie/) to automate discovery of sensitive data that is uploaded to your S3 bucket


## Securing EC2 instance

To futher secure your EC2 instance, you may want to
- Restrict remote administration access to your IP address only (`ingressIPv4` and `ingressIPv6`)
- Disable SSH access from public internet (`allowSSHport`). Use [EC2 Instance Connect](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-connect-methods.html#ec2-instance-connect-connecting-console) or [SSM Session Manager](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-sessions-start.html#start-ec2-console) for in-browser terminal access. If you have [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) and [Session Manager plugin for the AWS CLI](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html) installed, you can start a session using [AWS CLI](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-sessions-start.html#sessions-start-cli) or [SSH](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-sessions-start.html#sessions-start-ssh)
- Remove NICE DCV web browser client package by running the command `sudo apt remove -y nice-dcv-web-viewer`. Connect using native Windows, MacOS or Linux [client](https://docs.aws.amazon.com/dcv/latest/userguide/client.html)
- Deploy EC2 instance in a private subnet. Use [Application Load Balancer](https://aws.amazon.com/elasticloadbalancing/application-load-balancer/) and [AWS WAF](https://aws.amazon.com/waf/) to [protect your EC2 instance](https://repost.aws/knowledge-center/waf-protect-ec2-instance). You can use [AWS Certificate Manager](https://aws.amazon.com/certificate-manager/) to [request a public HTTPS certificate](https://docs.aws.amazon.com/acm/latest/userguide/gs-acm-request-public.html) and [associate it](https://repost.aws/knowledge-center/associate-acm-certificate-alb-nlb) with your Application Load Balancer
- Enable [Amazon Inspector](https://docs.aws.amazon.com/inspector/latest/user/what-is-inspector.html) to automatically scan EC2 instance for software vulnerabilities and unintended network exposure
- Enable [Amazon GuardDuty](https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html) and [GuardDuty Malware Protection for EC2](https://docs.aws.amazon.com/guardduty/latest/ug/malware-protection.html) to detect potentially malicious activity in your AWS account

## Clean Up
To remove created resources,
- [Empty](https://docs.aws.amazon.com/AmazonS3/latest/userguide/empty-bucket.html) created S3 bucket(s)
- [Delete](https://docs.aws.amazon.com/aws-backup/latest/devguide/deleting-backups.html) recovery points in created backup vault
- [Disable](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_ChangingDisableAPITermination.html) EC2 instance termination protection
- [Delete](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-console-delete-stack.html) CloudFormation stack


## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.
