AWSTemplateFormatVersion: 2010-09-09
Description: Nextcloud ( https://github.com/aws-samples/nextcloud-server ) (uksb-kole4t76z0) (tag:Ubuntu)
Transform: "AWS::LanguageExtensions"

Metadata:
  License:
    Description: >
      Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
      SPDX-License-Identifier: MIT-0

      Permission is hereby granted, free of charge, to any person obtaining a copy of this
      software and associated documentation files (the "Software"), to deal in the Software
      without restriction, including without limitation the rights to use, copy, modify,
      merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
      permit persons to whom the Software is furnished to do so.

      THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
      INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
      PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
      HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
      OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
      SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
  AWS::CloudFormation::Interface:
    ParameterGroups:
      - Label:
          default: EC2 instance
        Parameters:
          - ec2Name
          - ec2KeyPair
          - osVersion
          - instanceType
          - ec2TerminationProtection
      - Label:
          default: Network
        Parameters:
          - vpcID
          - subnetID
          - displayPublicIP
          - assignStaticIP
      - Label:
          default: Remote administration
        Parameters:
          - ingressIPv4
          - ingressIPv6
          - allowSSHport
          - installDCV
          - installWebmin
      - Label:
          default: Nextcloud
        Parameters:
          - adminUsername
          - phpVersion
          - databaseOption
          - r53ZoneID
      - Label:
          default: S3
        Parameters:
          - s3StorageClass
          - enableS3BucketLogging
      - Label:
          default: S3 External Storage
        Parameters:
          - externalS3Bucket
          - externalS3BucketRegion
          - externalS3BucketStorageClass
      - Label:
          default: EBS volume
        Parameters:
          - volumeSize
          - volumeType
      - Label:
          default: AWS Backup
        Parameters:
          - backupResource
          - scheduleExpression
          - scheduleExpressionTimezone
          - deleteAfterDays
    ParameterLabels:
      osVersion:
        default: "OS version and architecture"
      instanceType:
        default: "Instance type (x86_64 or arm64)"
      ec2Name:
        default: "Instance name"
      ec2KeyPair:
        default: "Keypair name"
      ec2TerminationProtection:
        default: "Enable EC2 termination protection to prevent accidental deletion"

      volumeSize:
        default: "Volume size (GiB)"
      volumeType:
        default: "Volume type"

      vpcID:
        default: "VPC with internet connectivity"
      subnetID:
        default: "Subnet with internet connectivity"
      displayPublicIP:
        default: "EC2 in public subnet with public IP assigned?"
      assignStaticIP:
        default: "[Elastic IP] Assign static public internet IPv4 address"

      ingressIPv4:
        default: "Allowed IPv4 prefix"
      ingressIPv6:
        default: "Allowed IPv6 prefix"
      allowSSHport:
        default: "Allow SSH from network"
      installDCV:
        default: "Install graphical desktop environment and DCV server"
      installWebmin:
        default: "Install Webmin web-based system administration tool"

      adminUsername:
        default: "Nextcloud admin username"
      phpVersion:
        default: "PHP version to install"
      r53ZoneID:
        default: "(Optional) Route 53 hosted zone ID for certbot-dns-route53 access. Leave blank not to grant"
      databaseOption:
        default: "Database server to install"

      s3StorageClass:
        default: "Storage class for primary storage ( https://docs.aws.amazon.com/AmazonS3/latest/userguide/storage-class-intro.html#sc-compare )"
      enableS3BucketLogging:
        default: "Enable primary storage S3 server access logging"
      externalS3Bucket:
        default: "(Optional) Existing S3 bucket to mount as external storage. Leave blank for none"
      externalS3BucketRegion:
        default: "Region where external storage S3 bucket is located"

      backupResource:
        default: "Resources to backup"
      scheduleExpression:
        default: "CRON expression specifying when AWS Backup initiates a backup job"
      scheduleExpressionTimezone:
        default: "Timezone to set backup schedule"
      deleteAfterDays:
        default: "Number of days after creation that a recovery point (backup) is deleted"

Parameters:
  osVersion:
    Type: String
    Description: https://aws.amazon.com/ec2/graviton/ https://ubuntu.com/aws/pro
    AllowedValues:
      - Ubuntu 24.04 (arm64)
      - Ubuntu 24.04 (x86_64)
      - Ubuntu 22.04 (arm64)
      - Ubuntu 22.04 (x86_64)
      - Ubuntu Pro 24.04 (arm64)
      - Ubuntu Pro 24.04 (x86_64)
      - Ubuntu Pro 22.04 (arm64)
      - Ubuntu Pro 22.04 (x86_64)
    Default: Ubuntu 22.04 (arm64)
  instanceType:
    Type: String
    Description: "https://console.aws.amazon.com/ec2/#InstanceTypes"
    Default: t4g.xlarge

  ec2Name:
    Type: String
    Default: Nextcloud
  ec2KeyPair:
    Type: AWS::EC2::KeyPair::KeyName
    Description: https://console.aws.amazon.com/ec2/#KeyPairs
    ConstraintDescription: Specify a key pair
    AllowedPattern: ".+"
  ec2TerminationProtection:
    Type: String
    Description: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_ChangingDisableAPITermination.html
    Default: "Yes"
    AllowedValues:
      - "Yes"
      - "No"

  vpcID:
    Type: AWS::EC2::VPC::Id
    Description: "https://console.aws.amazon.com/vpcconsole/home#vpcs:"
    ConstraintDescription: Specify a valid value
    AllowedPattern: ".+"
  subnetID:
    Type: AWS::EC2::Subnet::Id
    Description: "https://console.aws.amazon.com/vpcconsole/home#subnets:"
    ConstraintDescription: Specify a valid value
    AllowedPattern: ".+"
  assignStaticIP:
    Type: String
    Description: "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html"
    AllowedValues:
      - "Yes"
      - "No"
    Default: "Yes"
  displayPublicIP:
    Type: String
    Description: "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html#concepts-public-addresses"
    AllowedValues:
      - "Yes"
      - "No"
    Default: "Yes"

  ingressIPv4:
    Type: String
    Description: "e.g. 1.2.3.4/32, get your source IP from https://checkip.amazonaws.com "
    Default: 0.0.0.0/0
  ingressIPv6:
    Type: String
    Description: "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html#ipv6-addressing"
    Default: ::/0
  allowSSHport:
    Type: String
    AllowedValues:
      - "Yes"
      - "No"
    Default: "No"
  installDCV:
    Type: String
    Description: https://aws.amazon.com/hpc/dcv/
    AllowedValues:
      - "Yes"
      - "No"
    Default: "No"
  installWebmin:
    Type: String
    Description: https://webmin.com/
    AllowedValues:
      - "Yes"
      - "No"
    Default: "No"

  adminUsername:
    Type: String
    AllowedPattern: ".+"
    Default: "admin"
  phpVersion:
    Type: String
    AllowedValues:
      - "php8.3"
      - "php8.4"
    Default: "php8.3"
  databaseOption:
    Type: String
    AllowedValues:
      - "MariaDB"
      - "MySQL"
    Default: "MariaDB"
  r53ZoneID:
    Type: String
    Description: https://console.aws.amazon.com/route53/v2/hostedzones
    Default: ""

  s3StorageClass:
    Type: String
    AllowedValues:
      - GLACIER_IR
      - INTELLIGENT_TIERING
      - ONEZONE_IA
      - STANDARD
      - STANDARD_IA
    Default: STANDARD
  enableS3BucketLogging:
    Type: String
    Description: https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-server-access-logging.html
    AllowedValues:
      - "Yes"
      - "No"
    Default: "No"

  externalS3Bucket:
    Type: String
    Description: https://console.aws.amazon.com/s3/home
    Default: ""
  externalS3BucketRegion:
    Type: String
    AllowedValues:
      - af-south-1
      - ap-east-1
      - ap-northeast-1
      - ap-northeast-2
      - ap-northeast-3
      - ap-south-1
      - ap-south-2
      - ap-southeast-1
      - ap-southeast-2
      - ap-southeast-3
      - ap-southeast-4
      - ap-southeast-5
      - ap-southeast-7
      - ca-central-1
      - ca-west-1
      - cn-north-1
      - cn-northwest-1
      - eu-central-1
      - eu-central-2
      - eu-north-1
      - eu-south-1
      - eu-south-2
      - eu-west-1
      - eu-west-2
      - eu-west-3
      - il-central-1
      - me-central-1
      - me-south-1
      - mx-central-1
      - sa-east-1
      - us-east-1
      - us-east-2
      - us-gov-east-1
      - us-gov-west-1
      - us-west-1
      - us-west-2
    Default: us-east-1
  externalS3BucketStorageClass:
    Type: String
    AllowedValues:
      - GLACIER_IR
      - INTELLIGENT_TIERING
      - ONEZONE_IA
      - STANDARD
      - STANDARD_IA
    Default: STANDARD

  volumeSize:
    Type: Number
    Description: https://github.com/nextcloud/server/issues/40539
    MinValue: 10
    MaxValue: 16384
    Default: 65
  volumeType:
    Type: String
    Description: https://aws.amazon.com/ebs/general-purpose/
    AllowedValues:
      - "gp3"
      - "gp2"
    Default: "gp3"

  backupResource:
    Type: String
    AllowedValues:
      - EC2
      - S3
      - ExternalStorage
      - EC2-and-S3
      - All
      - none
    Default: "EC2-and-S3"
  scheduleExpression:
    Type: String
    AllowedPattern: ".+"
    Default: "cron(0 1 ? * * *)"
  scheduleExpressionTimezone: # https://nodatime.org/TimeZones?version=2024a&format=json
    Type: String
    AllowedValues:
      - Africa/Abidjan
      - Africa/Algiers
      - Africa/Bissau
      - Africa/Cairo
      - Africa/Casablanca
      - Africa/Ceuta
      - Africa/El_Aaiun
      - Africa/Johannesburg
      - Africa/Juba
      - Africa/Khartoum
      - Africa/Lagos
      - Africa/Maputo
      - Africa/Monrovia
      - Africa/Nairobi
      - Africa/Ndjamena
      - Africa/Sao_Tome
      - Africa/Tripoli
      - Africa/Tunis
      - Africa/Windhoek
      - America/Adak
      - America/Anchorage
      - America/Araguaina
      - America/Argentina/Buenos_Aires
      - America/Argentina/Catamarca
      - America/Argentina/Cordoba
      - America/Argentina/Jujuy
      - America/Argentina/La_Rioja
      - America/Argentina/Mendoza
      - America/Argentina/Rio_Gallegos
      - America/Argentina/Salta
      - America/Argentina/San_Juan
      - America/Argentina/San_Luis
      - America/Argentina/Tucuman
      - America/Argentina/Ushuaia
      - America/Asuncion
      - America/Bahia
      - America/Bahia_Banderas
      - America/Barbados
      - America/Belem
      - America/Belize
      - America/Boa_Vista
      - America/Bogota
      - America/Boise
      - America/Cambridge_Bay
      - America/Campo_Grande
      - America/Cancun
      - America/Caracas
      - America/Cayenne
      - America/Chicago
      - America/Chihuahua
      - America/Ciudad_Juarez
      - America/Costa_Rica
      - America/Cuiaba
      - America/Danmarkshavn
      - America/Dawson
      - America/Dawson_Creek
      - America/Denver
      - America/Detroit
      - America/Edmonton
      - America/Eirunepe
      - America/El_Salvador
      - America/Fort_Nelson
      - America/Fortaleza
      - America/Glace_Bay
      - America/Goose_Bay
      - America/Grand_Turk
      - America/Guatemala
      - America/Guayaquil
      - America/Guyana
      - America/Halifax
      - America/Havana
      - America/Hermosillo
      - America/Indiana/Indianapolis
      - America/Indiana/Knox
      - America/Indiana/Marengo
      - America/Indiana/Petersburg
      - America/Indiana/Tell_City
      - America/Indiana/Vevay
      - America/Indiana/Vincennes
      - America/Indiana/Winamac
      - America/Inuvik
      - America/Iqaluit
      - America/Jamaica
      - America/Juneau
      - America/Kentucky/Louisville
      - America/Kentucky/Monticello
      - America/La_Paz
      - America/Lima
      - America/Los_Angeles
      - America/Maceio
      - America/Managua
      - America/Manaus
      - America/Martinique
      - America/Matamoros
      - America/Mazatlan
      - America/Menominee
      - America/Merida
      - America/Metlakatla
      - America/Mexico_City
      - America/Miquelon
      - America/Moncton
      - America/Monterrey
      - America/Montevideo
      - America/New_York
      - America/Nome
      - America/Noronha
      - America/North_Dakota/Beulah
      - America/North_Dakota/Center
      - America/North_Dakota/New_Salem
      - America/Nuuk
      - America/Ojinaga
      - America/Panama
      - America/Paramaribo
      - America/Phoenix
      - America/Port-au-Prince
      - America/Porto_Velho
      - America/Puerto_Rico
      - America/Punta_Arenas
      - America/Rankin_Inlet
      - America/Recife
      - America/Regina
      - America/Resolute
      - America/Rio_Branco
      - America/Santarem
      - America/Santiago
      - America/Santo_Domingo
      - America/Sao_Paulo
      - America/Scoresbysund
      - America/Sitka
      - America/St_Johns
      - America/Swift_Current
      - America/Tegucigalpa
      - America/Thule
      - America/Tijuana
      - America/Toronto
      - America/Vancouver
      - America/Whitehorse
      - America/Winnipeg
      - America/Yakutat
      - Antarctica/Casey
      - Antarctica/Davis
      - Antarctica/Macquarie
      - Antarctica/Mawson
      - Antarctica/Palmer
      - Antarctica/Rothera
      - Antarctica/Troll
      - Antarctica/Vostok
      - Asia/Almaty
      - Asia/Amman
      - Asia/Anadyr
      - Asia/Aqtau
      - Asia/Aqtobe
      - Asia/Ashgabat
      - Asia/Atyrau
      - Asia/Baghdad
      - Asia/Baku
      - Asia/Bangkok
      - Asia/Barnaul
      - Asia/Beirut
      - Asia/Bishkek
      - Asia/Chita
      - Asia/Choibalsan
      - Asia/Colombo
      - Asia/Damascus
      - Asia/Dhaka
      - Asia/Dili
      - Asia/Dubai
      - Asia/Dushanbe
      - Asia/Famagusta
      - Asia/Gaza
      - Asia/Hebron
      - Asia/Ho_Chi_Minh
      - Asia/Hong_Kong
      - Asia/Hovd
      - Asia/Irkutsk
      - Asia/Jakarta
      - Asia/Jayapura
      - Asia/Jerusalem
      - Asia/Kabul
      - Asia/Kamchatka
      - Asia/Karachi
      - Asia/Kathmandu
      - Asia/Khandyga
      - Asia/Kolkata
      - Asia/Krasnoyarsk
      - Asia/Kuching
      - Asia/Macau
      - Asia/Magadan
      - Asia/Makassar
      - Asia/Manila
      - Asia/Nicosia
      - Asia/Novokuznetsk
      - Asia/Novosibirsk
      - Asia/Omsk
      - Asia/Oral
      - Asia/Pontianak
      - Asia/Pyongyang
      - Asia/Qatar
      - Asia/Qostanay
      - Asia/Qyzylorda
      - Asia/Riyadh
      - Asia/Sakhalin
      - Asia/Samarkand
      - Asia/Seoul
      - Asia/Shanghai
      - Asia/Singapore
      - Asia/Srednekolymsk
      - Asia/Taipei
      - Asia/Tashkent
      - Asia/Tbilisi
      - Asia/Tehran
      - Asia/Thimphu
      - Asia/Tokyo
      - Asia/Tomsk
      - Asia/Ulaanbaatar
      - Asia/Urumqi
      - Asia/Ust-Nera
      - Asia/Vladivostok
      - Asia/Yakutsk
      - Asia/Yangon
      - Asia/Yekaterinburg
      - Asia/Yerevan
      - Atlantic/Azores
      - Atlantic/Bermuda
      - Atlantic/Canary
      - Atlantic/Cape_Verde
      - Atlantic/Faroe
      - Atlantic/Madeira
      - Atlantic/South_Georgia
      - Atlantic/Stanley
      - Australia/Adelaide
      - Australia/Brisbane
      - Australia/Broken_Hill
      - Australia/Darwin
      - Australia/Eucla
      - Australia/Hobart
      - Australia/Lindeman
      - Australia/Lord_Howe
      - Australia/Melbourne
      - Australia/Perth
      - Australia/Sydney
      - CET
      - CST6CDT
      - EET
      - EST
      - EST5EDT
      - Etc/GMT
      - Etc/GMT+1
      - Etc/GMT+10
      - Etc/GMT+11
      - Etc/GMT+12
      - Etc/GMT+2
      - Etc/GMT+3
      - Etc/GMT+4
      - Etc/GMT+5
      - Etc/GMT+6
      - Etc/GMT+7
      - Etc/GMT+8
      - Etc/GMT+9
      - Etc/GMT-1
      - Etc/GMT-10
      - Etc/GMT-11
      - Etc/GMT-12
      - Etc/GMT-13
      - Etc/GMT-14
      - Etc/GMT-2
      - Etc/GMT-3
      - Etc/GMT-4
      - Etc/GMT-5
      - Etc/GMT-6
      - Etc/GMT-7
      - Etc/GMT-8
      - Etc/GMT-9
      - Etc/UTC
      - Europe/Andorra
      - Europe/Astrakhan
      - Europe/Athens
      - Europe/Belgrade
      - Europe/Berlin
      - Europe/Brussels
      - Europe/Bucharest
      - Europe/Budapest
      - Europe/Chisinau
      - Europe/Dublin
      - Europe/Gibraltar
      - Europe/Helsinki
      - Europe/Istanbul
      - Europe/Kaliningrad
      - Europe/Kirov
      - Europe/Kyiv
      - Europe/Lisbon
      - Europe/London
      - Europe/Madrid
      - Europe/Malta
      - Europe/Minsk
      - Europe/Moscow
      - Europe/Paris
      - Europe/Prague
      - Europe/Riga
      - Europe/Rome
      - Europe/Samara
      - Europe/Saratov
      - Europe/Simferopol
      - Europe/Sofia
      - Europe/Tallinn
      - Europe/Tirane
      - Europe/Ulyanovsk
      - Europe/Vienna
      - Europe/Vilnius
      - Europe/Volgograd
      - Europe/Warsaw
      - Europe/Zurich
      - HST
      - Indian/Chagos
      - Indian/Maldives
      - Indian/Mauritius
      - MET
      - MST
      - MST7MDT
      - PST8PDT
      - Pacific/Apia
      - Pacific/Auckland
      - Pacific/Bougainville
      - Pacific/Chatham
      - Pacific/Easter
      - Pacific/Efate
      - Pacific/Fakaofo
      - Pacific/Fiji
      - Pacific/Galapagos
      - Pacific/Gambier
      - Pacific/Guadalcanal
      - Pacific/Guam
      - Pacific/Honolulu
      - Pacific/Kanton
      - Pacific/Kiritimati
      - Pacific/Kosrae
      - Pacific/Kwajalein
      - Pacific/Marquesas
      - Pacific/Nauru
      - Pacific/Niue
      - Pacific/Norfolk
      - Pacific/Noumea
      - Pacific/Pago_Pago
      - Pacific/Palau
      - Pacific/Pitcairn
      - Pacific/Port_Moresby
      - Pacific/Rarotonga
      - Pacific/Tahiti
      - Pacific/Tarawa
      - Pacific/Tongatapu
      - WET
    Default: Etc/UTC
  deleteAfterDays:
    Type: Number
    Default: 35

Conditions:
  useUbuntu2404x86: !Equals [!Ref osVersion, "Ubuntu 24.04 (x86_64)"]
  useUbuntu2404arm64: !Equals [!Ref osVersion, "Ubuntu 24.04 (arm64)"]
  useUbuntu2204x86: !Equals [!Ref osVersion, "Ubuntu 22.04 (x86_64)"]
  useUbuntu2204arm64: !Equals [!Ref osVersion, "Ubuntu 22.04 (arm64)"]
  useUbuntuPro2404x86: !Equals [!Ref osVersion, "Ubuntu Pro 24.04 (x86_64)"]
  useUbuntuPro2404arm64: !Equals [!Ref osVersion, "Ubuntu Pro 24.04 (arm64)"]
  useUbuntuPro2204x86: !Equals [!Ref osVersion, "Ubuntu Pro 22.04 (x86_64)"]

  useElasticIP: !Equals [!Ref assignStaticIP, "Yes"]
  displayPublicIP: !Equals [!Ref displayPublicIP, "Yes"]
  enableProtection: !Equals [!Ref ec2TerminationProtection, "Yes"]
  hasEIC:
    !Not [
      !Equals [
        !FindInMap [
          EICprefixMap,
          !Ref AWS::Region,
          IpPrefix,
          DefaultValue: 127.0.0.1/32,
        ],
        127.0.0.1/32,
      ],
    ]
  createSgEIC: !And [!Condition hasEIC, !Condition displayPublicIP]
  createSgSSH: !Equals [!Ref allowSSHport, "Yes"]

  installDCV: !Equals [!Ref installDCV, "Yes"]
  noDCV: !Not [!Condition installDCV]
  installWebmin: !Equals [!Ref installWebmin, "Yes"]
  hasR53Zone: !Not [!Equals [!Ref r53ZoneID, ""]]

  enableS3BucketLogging: !Equals [!Ref enableS3BucketLogging, "Yes"]
  noS3BucketLogging: !Not [!Condition enableS3BucketLogging]
  externalS3Bucket: !Not [!Equals [!Ref externalS3Bucket, ""]]

  backupEC2:
    !Or [
      !Equals [!Ref backupResource, "EC2"],
      !Or [
        !Equals [!Ref backupResource, "EC2-and-S3"],
        !Equals [!Ref backupResource, "All"],
      ],
    ]
  backupS3:
    !Or [
      !Equals [!Ref backupResource, "S3"],
      !Or [
        !Equals [!Ref backupResource, "EC2-and-S3"],
        !Equals [!Ref backupResource, "All"],
      ],
    ]
  backupExternalStorage:
    !And [
      !Condition externalS3Bucket,
      !Or [
        !Equals [!Ref backupResource, "ExternalStorage"],
        !Equals [!Ref backupResource, "All"],
      ],
    ]
  createBackup:
    !Or [
      !Condition backupEC2,
      !Or [!Condition backupS3, !Condition backupExternalStorage],
    ]

Mappings:
  EICprefixMap: # EC2 instance connect: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-connect-prerequisites.html#ec2-instance-connect-setup-security-group
    af-south-1:
      IpPrefix: 13.244.121.196/30
      Ipv6Prefix: 2406:da11:700:3b00::/56
    ap-east-1:
      IpPrefix: 43.198.192.104/29
      Ipv6Prefix: 2406:da1e:da1:3c00::/56
    ap-northeast-1:
      IpPrefix: 3.112.23.0/29
      Ipv6Prefix: 2406:da14:1c18:2100::/56
    ap-northeast-2:
      IpPrefix: 13.209.1.56/29
      Ipv6Prefix: 2406:da12:1e1:d900::/56
    ap-northeast-3:
      IpPrefix: 15.168.105.160/29
      Ipv6Prefix: 2406:da16:856:a500::/56
    ap-south-1:
      IpPrefix: 13.233.177.0/29
      Ipv6Prefix: 2406:da1a:74a:4b00::/56
    ap-south-2:
      IpPrefix: 18.60.252.248/29
      Ipv6Prefix: 2406:da1b:d1d:8800::/56
    ap-southeast-1:
      IpPrefix: 3.0.5.32/29
      Ipv6Prefix: 2406:da18:752:6600::/56
    ap-southeast-2:
      IpPrefix: 13.239.158.0/29
      Ipv6Prefix: 2406:da1c:90e:4a00::/56
    ap-southeast-3:
      IpPrefix: 43.218.193.64/29
      Ipv6Prefix: 2406:da19:14b:8c00::/56
    ap-southeast-4:
      IpPrefix: 16.50.248.80/29
      Ipv6Prefix: 2406:da1f:b4f:4600::/56
    ca-central-1:
      IpPrefix: 35.183.92.176/29
      Ipv6Prefix: 2600:1f11:ae3:700::/56
    ca-west-1:
      IpPrefix: 40.176.213.168/29
      Ipv6Prefix: 2600:1f1a:4ff6:d500::/56
    cn-north-1:
      IpPrefix: 43.196.20.40/29
      Ipv6Prefix: 2400:7fc0:86fd:e00::/56
    cn-northwest-1:
      IpPrefix: 43.192.155.8/29
      Ipv6Prefix: 2404:c2c0:87aa:4800::/56
    eu-central-1:
      IpPrefix: 3.120.181.40/29
      Ipv6Prefix: 2a05:d014:17a8:8b00::/56
    eu-central-2:
      IpPrefix: 16.63.77.8/29
      Ipv6Prefix: 2a05:d019:1d6:2100::/56
    eu-north-1:
      IpPrefix: 13.48.4.200/30
      Ipv6Prefix: 2a05:d016:494:f00::/56
    eu-south-1:
      IpPrefix: 15.161.135.164/30
      Ipv6Prefix: 2a05:d01a:c03:4a00::/56
    eu-south-2:
      IpPrefix: 18.101.90.48/29
      Ipv6Prefix: 2a05:d011:cbe:f700::/56
    eu-west-1:
      IpPrefix: 18.202.216.48/29
      Ipv6Prefix: 2a05:d018:403:4e00::/56
    eu-west-2:
      IpPrefix: 3.8.37.24/29
      Ipv6Prefix: 2a05:d01c:4ac:3100::/56
    eu-west-3:
      IpPrefix: 35.180.112.80/29
      Ipv6Prefix: 2a05:d012:c9e:d600::/56
    il-central-1:
      IpPrefix: 51.16.183.224/29
      Ipv6Prefix: 2a05:d025:451:7d00::/56
    me-central-1:
      IpPrefix: 3.29.147.40/29
      Ipv6Prefix: 2406:da17:1db:b00::/56
    me-south-1:
      IpPrefix: 16.24.46.56/29
      Ipv6Prefix: 2a05:d01e:27f:ac00::/56
    sa-east-1:
      IpPrefix: 18.228.70.32/29
      Ipv6Prefix: 2600:1f1e:d1d:e700::/56
    us-east-1:
      IpPrefix: 18.206.107.24/29
      Ipv6Prefix: 2600:1f18:6fe3:8c00::/56
    us-east-2:
      IpPrefix: 3.16.146.0/29
      Ipv6Prefix: 2600:1f16:138f:cf00::/56
    us-gov-east-1:
      IpPrefix: 18.252.4.0/30
      Ipv6Prefix: 2600:1f15:d63:bd00::/56
    us-gov-west-1:
      IpPrefix: 15.200.28.80/30
      Ipv6Prefix: 2600:1f12:fa9:5100::/56
    us-west-1:
      IpPrefix: 13.52.6.112/29
      Ipv6Prefix: 2600:1f1c:12d:e900::/56
    us-west-2:
      IpPrefix: 18.237.140.160/29
      Ipv6Prefix: 2600:1f13:a0d:a700::/56

Resources:
  instanceIamRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: [ec2.amazonaws.com]
            Action: [sts:AssumeRole]
      Path: /
      Policies:
        - PolicyName: Nextcloud-S3PrimaryStoragePolicy
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                  - s3:*
                Resource:
                  - !If [
                      noS3BucketLogging,
                      !Sub "arn:${AWS::Partition}:s3:::${s3Bucket}",
                      !Sub "arn:${AWS::Partition}:s3:::${s3BucketWithLogging}",
                    ]
                  - !If [
                      noS3BucketLogging,
                      !Sub "arn:${AWS::Partition}:s3:::${s3Bucket}/*",
                      !Sub "arn:${AWS::Partition}:s3:::${s3BucketWithLogging}/*",
                    ]
                Condition:
                  IpAddress:
                    aws:SourceIp: 0.0.0.0/0
        - !If
          - installDCV
          - PolicyName: dcvLicensing
            PolicyDocument: # https://docs.aws.amazon.com/dcv/latest/adminguide/setting-up-license.html
              Version: "2012-10-17"
              Statement:
                - Effect: Allow
                  Action:
                    - s3:GetObject
                  Resource: !Sub arn:*:s3:::dcv-license.${AWS::Region}/*
          - !Ref AWS::NoValue
        - !If
          - hasR53Zone
          - PolicyName: Route53CertbotAccess
            PolicyDocument: # Certbot dns_route53 : https://certbot-dns-route53.readthedocs.io/en/stable/
              Version: "2012-10-17"
              Statement: # https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/specifying-rrset-conditions.html
                - Effect: Allow
                  Action:
                    - route53:ListHostedZones
                    - route53:GetChange
                  Resource: "*"
                - Effect: Allow
                  Action:
                    - route53:ChangeResourceRecordSets
                  Resource: !Sub arn:${AWS::Partition}:route53:::hostedzone/${r53ZoneID}
                  Condition:
                    IpAddress:
                      aws:SourceIp: 0.0.0.0/0
                    ForAllValues:StringEquals:
                      route53:ChangeResourceRecordSetsRecordTypes: [TXT]
                    ForAllValues:StringLike:
                      route53:ChangeResourceRecordSetsNormalizedRecordNames:
                        [_acme-challenge.*]
          - !Ref AWS::NoValue
      ManagedPolicyArns:
        - !Sub "arn:${AWS::Partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
        - !Sub "arn:${AWS::Partition}:iam::aws:policy/CloudWatchAgentServerPolicy"
      Tags:
        - Key: StackName
          Value: !Ref AWS::StackName
        - Key: StackId
          Value: !Ref AWS::StackId
        - Key: GitHub
          Value: https://github.com/aws-samples/nextcloud-server

  instanceProfile:
    Type: AWS::IAM::InstanceProfile
    Properties:
      Path: /
      Roles:
        - !Ref instanceIamRole

  securityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Allow inbound HTTP, HTTPS and any remote admin ports
      VpcId: !Ref vpcID
      SecurityGroupIngress:
        - !If
          - installWebmin
          - Description: Webmin (IPv4)
            IpProtocol: tcp
            FromPort: 10000
            ToPort: 10000
            CidrIp: !Ref ingressIPv4
          - !Ref AWS::NoValue
        - !If
          - installWebmin
          - Description: Webmin (IPv6)
            IpProtocol: tcp
            FromPort: 10000
            ToPort: 10000
            CidrIpv6: !Ref ingressIPv6
          - !Ref AWS::NoValue
        - !If
          - createSgSSH
          - Description: SSH (IPv4)
            IpProtocol: tcp
            FromPort: 22
            ToPort: 22
            CidrIp: !Ref ingressIPv4
          - !Ref AWS::NoValue
        - !If
          - createSgSSH
          - Description: SSH (IPv6)
            IpProtocol: tcp
            FromPort: 22
            ToPort: 22
            CidrIpv6: !Ref ingressIPv6
          - !Ref AWS::NoValue
        - !If
          - installDCV
          - Description: DCV (IPv4)
            IpProtocol: tcp
            FromPort: 8443
            ToPort: 8443
            CidrIp: !Ref ingressIPv4
          - !Ref AWS::NoValue
        - !If
          - installDCV
          - Description: DCV (IPv6)
            IpProtocol: tcp
            FromPort: 8443
            ToPort: 8443
            CidrIpv6: !Ref ingressIPv6
          - !Ref AWS::NoValue
        - !If
          - installDCV
          - Description: DCV QUIC (IPv4)
            IpProtocol: udp
            FromPort: 8443
            ToPort: 8443
            CidrIp: !Ref ingressIPv4
          - !Ref AWS::NoValue
        - !If
          - installDCV
          - Description: DCV QUIC (IPv6)
            IpProtocol: udp
            FromPort: 8443
            ToPort: 8443
            CidrIpv6: !Ref ingressIPv6
          - !Ref AWS::NoValue
        - Description: HTTP (IPv4)
          IpProtocol: tcp
          FromPort: 80
          ToPort: 80
          CidrIp: 0.0.0.0/0
        - Description: HTTP (IPv6)
          IpProtocol: tcp
          FromPort: 80
          ToPort: 80
          CidrIpv6: ::/0
        - Description: HTTPS (IPv4)
          IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          CidrIp: 0.0.0.0/0
        - Description: HTTPS (IPv6)
          IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          CidrIpv6: ::/0
        - !If
          - createSgEIC
          - Description: SSH (EC2 Instance Connect IPv4)
            IpProtocol: tcp
            FromPort: 22
            ToPort: 22
            CidrIp: !FindInMap [EICprefixMap, !Ref AWS::Region, IpPrefix]
          - !Ref AWS::NoValue
        - !If
          - createSgEIC
          - Description: SSH (EC2 Instance Connect IPv6)
            IpProtocol: tcp
            FromPort: 22
            ToPort: 22
            CidrIpv6: !FindInMap [EICprefixMap, !Ref AWS::Region, Ipv6Prefix]
          - !Ref AWS::NoValue
      SecurityGroupEgress:
        - Description: Allow all outbound traffic (IPv4)
          IpProtocol: "-1"
          CidrIp: 0.0.0.0/0
        - Description: Allow all outbound traffic (IPv6)
          IpProtocol: "-1"
          CidrIpv6: ::/0
      Tags:
        - Key: StackName
          Value: !Ref AWS::StackName
        - Key: StackId
          Value: !Ref AWS::StackId
        - Key: Name
          Value: !Sub
            - "${AWS::StackName}-securityGroup-${UID}"
            - UID:
                !Select [
                  3,
                  !Split ["-", !Select [2, !Split ["/", !Ref AWS::StackId]]],
                ]
        - Key: GitHub
          Value: https://github.com/aws-samples/nextcloud-server

  iamUser:
    Type: AWS::IAM::User
    Properties:
      Tags:
        - Key: StackName
          Value: !Ref AWS::StackName
        - Key: StackId
          Value: !Ref AWS::StackId
        - Key: GitHub
          Value: https://github.com/aws-samples/nextcloud-server

  iamGroup:
    Type: AWS::IAM::Group
    Properties:

  iamS3ExternalStoragePolicy:
    Type: AWS::IAM::GroupPolicy
    Condition: externalS3Bucket
    Properties:
      GroupName: !Ref iamGroup
      PolicyName: !Sub
        - "${AWS::StackName}-iamS3ExternalStoragePolicy-${UID}"
        - UID:
            !Select [
              3,
              !Split ["-", !Select [2, !Split ["/", !Ref AWS::StackId]]],
            ]
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Action:
              - s3:PutObject
              - s3:GetObject
              - s3:GetObjectAttributes
              - s3:ListBucket
              - s3:GetBucketVersioning
              - s3:DeleteObject
              - s3:AbortMultipartUpload
            Resource:
              - !Sub "arn:${AWS::Partition}:s3:::${externalS3Bucket}"
              - !Sub "arn:${AWS::Partition}:s3:::${externalS3Bucket}/*"
            Condition:
              IpAddress:
                aws:SourceIp: 0.0.0.0/0

  iamUserToGroup:
    Type: AWS::IAM::UserToGroupAddition
    Properties:
      GroupName: !Ref iamGroup
      Users:
        - !Ref iamUser

  userAccessKey:
    Type: AWS::IAM::AccessKey
    Properties:
      UserName: !Ref iamUser

  s3Bucket:
    Type: AWS::S3::Bucket
    Condition: noS3BucketLogging
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - BucketKeyEnabled: true
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
      VersioningConfiguration:
        Status: Enabled
      LifecycleConfiguration:
        Rules:
          - Id: Delete-Incomplete-Multipart-Uploads
            AbortIncompleteMultipartUpload:
              DaysAfterInitiation: 35
            Status: Enabled
          - Id: Delete-Previous-Versions
            NoncurrentVersionExpiration:
              NoncurrentDays: 1
            Status: Enabled
          - Id: Delete-Expired-Delete-Marker
            ExpiredObjectDeleteMarker: true
            Status: Enabled
      Tags:
        - Key: StackName
          Value: !Ref AWS::StackName
        - Key: StackId
          Value: !Ref AWS::StackId
        - Key: GitHub
          Value: https://github.com/aws-samples/nextcloud-server

  s3BucketWithLogging:
    Type: AWS::S3::Bucket
    Condition: enableS3BucketLogging
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - BucketKeyEnabled: true
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
      VersioningConfiguration:
        Status: Enabled
      LifecycleConfiguration:
        Rules:
          - Id: Delete-Incomplete-Multipart-Uploads
            AbortIncompleteMultipartUpload:
              DaysAfterInitiation: 35
            Status: Enabled
          - Id: Delete-Previous-Versions
            NoncurrentVersionExpiration:
              NoncurrentDays: 1
            Status: Enabled
          - Id: Delete-Expired-Delete-Marker
            ExpiredObjectDeleteMarker: true
            Status: Enabled
      LoggingConfiguration:
        DestinationBucketName: !Ref logBucket
        LogFilePrefix: !Sub "${AWS::StackName}/"
      Tags:
        - Key: StackName
          Value: !Ref AWS::StackName
        - Key: StackId
          Value: !Ref AWS::StackId
        - Key: GitHub
          Value: https://github.com/aws-samples/nextcloud-server

  s3BucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: !If [noS3BucketLogging, !Ref s3Bucket, !Ref s3BucketWithLogging]
      PolicyDocument:
        Statement:
          - Effect: Deny
            Action:
              - s3:*
            Condition:
              Bool:
                "aws:SecureTransport": "false"
            Principal: "*"
            Resource:
              !If [
                noS3BucketLogging,
                !Sub "${s3Bucket.Arn}/*",
                !Sub "${s3BucketWithLogging.Arn}/*",
              ]

  logBucketPolicy:
    Type: AWS::S3::BucketPolicy
    Condition: enableS3BucketLogging
    Properties:
      Bucket: !Ref logBucket
      PolicyDocument: # https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-server-access-logging.html
        Statement:
          - Effect: Allow
            Principal:
              Service: logging.s3.amazonaws.com
            Action: s3:PutObject
            Resource: !Sub "${logBucket.Arn}/*"
            Condition:
              StringEquals:
                aws:SourceAccount: !Ref AWS::AccountId

  logBucket:
    Type: AWS::S3::Bucket
    Condition: enableS3BucketLogging
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - BucketKeyEnabled: true
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
      Tags:
        - Key: StackName
          Value: !Ref AWS::StackName
        - Key: StackId
          Value: !Ref AWS::StackId
        - Key: GitHub
          Value: https://github.com/aws-samples/nextcloud-server

  ec2Instance:
    Type: AWS::EC2::Instance
    CreationPolicy:
      ResourceSignal:
        Timeout: PT120M
    Metadata:
      Comment: Install Update files
      AWS::CloudFormation::Init:
        configSets:
          setup:
            - 00_setup
          dcv_install:
            - 00_dcv_install
          nextcloud_install:
            - 10_nextcloud_install
        00_setup: # in the following order: packages, groups, users, sources, files, commands, and then services.
          files:
            "/home/ubuntu/update-dcv":
              content: |
                #!/bin/bash
                cd /tmp
                OS_VERSION=$(. /etc/os-release;echo $VERSION_ID | sed -e 's/\.//g')
                sudo rm -f /tmp/nice-dcv-ubuntu$OS_VERSION-$(arch).tgz
                wget https://d1uj6qtbmh3dt5.cloudfront.net/nice-dcv-ubuntu$OS_VERSION-$(arch).tgz
                tar -xvzf nice-dcv-ubuntu$OS_VERSION-$(arch).tgz && cd nice-dcv-*-ubuntu$OS_VERSION-$(arch)
                sudo apt-get install -y ./nice-dcv-server_*.deb
                sudo apt-get install -y ./nice-dcv-web-viewer_*.deb
                sudo apt-get install -y ./nice-xdcv_*.deb
                sudo systemctl daemon-reload
              mode: "000755"
              owner: "ubuntu"
              group: "ubuntu"
            "/home/ubuntu/update-awscli":
              content: |
                #!/bin/bash
                cd /tmp
                sudo rm -f /tmp/awscliv2.zip
                curl https://awscli.amazonaws.com/awscli-exe-linux-$(arch).zip -o awscliv2.zip
                unzip -q -o awscliv2.zip
                /usr/bin/aws --version
                sudo ./aws/install --update -b /usr/bin
                /usr/bin/aws --version
              mode: "000755"
              owner: "ubuntu"
              group: "ubuntu"
            "/etc/systemd/system/dcv-virtual-session.service":
              content: |
                [Unit]
                Description=Create DCV virtual session
                After=default.target network.target

                [Service]
                ExecStart=/opt/dcv-virtual-session.sh

                [Install]
                WantedBy=default.target
              mode: "000644"
              owner: "root"
              group: "root"
            "/opt/dcv-virtual-session.sh":
              content: |
                #!/bin/bash
                dcvUsers=( "ubuntu" )
                while true;
                do
                  for dcvUser in "${dcvUsers[@]}"
                  do
                    if (! /usr/bin/dcv list-sessions | grep -q $dcvUser); then
                      /usr/bin/dcv create-session $dcvUser --owner $dcvUser --storage-root %home% --type virtual
                    fi
                  done
                  date
                  /usr/bin/dcv list-sessions
                  sleep 5
                done
              mode: "000744"
              owner: "root"
              group: "root"
            "/etc/systemd/system/dcv-post-reboot.service":
              content: |
                [Unit]
                Description=Post install tasks
                After=default.target network.target

                [Service]
                ExecStart=/bin/sh -c "/opt/dcv-post-reboot.sh 2>&1 | tee -a /var/log/install-sw.log"

                [Install]
                WantedBy=default.target
              mode: "000644"
              owner: "root"
              group: "root"
            "/opt/dcv-post-reboot.sh":
              content: !Sub |
                #!/bin/bash
                sysctl -w net.ipv6.conf.all.disable_ipv6=1
                sysctl -w net.ipv6.conf.default.disable_ipv6=1
                export DEBIAN_FRONTEND=noninteractive

                python3 /usr/local/bin/cfn-signal -e $? --stack ${AWS::StackName} --resource ec2Instance --region ${AWS::Region}

                apt-get update
                apt-get upgrade -q -y

                sysctl -w net.ipv6.conf.all.disable_ipv6=0
                sysctl -w net.ipv6.conf.default.disable_ipv6=0

                # DCV?
                export installDCV="${installDCV}"
                case $installDCV in
                  Yes)
                    systemctl enable dcv-virtual-session && systemctl restart dcv-virtual-session
                    systemctl enable dcvserver && systemctl restart dcvserver
                    ;;
                  No)
                    rm -f /etc/systemd/system/dcv-virtual-session.service
                    rm -f /opt/dcv-virtual-session.sh
                    rm -f /home/ubuntu/update-dcv
                    ;;
                esac

                rm -f /etc/systemd/system/dcv-post-reboot.service
                rm -f ${!0}
                systemctl daemon-reload
              mode: "000755"
              owner: "root"
              group: "root"
            "/opt/aws/amazon-cloudwatch-agent/bin/config.json":
              content: |
                {
                    "agent": {
                        "metrics_collection_interval": 60,
                        "run_as_user": "cwagent"
                    },
                    "logs": {
                      "logs_collected": {
                        "files": {
                          "collect_list": [
                            {
                              "file_path": "/var/www/html/data/nextcloud.log",
                              "log_group_class": "STANDARD",
                              "log_group_name": "nextcloud.log",
                              "log_stream_name": "{instance_id}",
                              "retention_in_days": 180
                            }
                          ]
                        }
                      }
                    },
                    "metrics": {
                        "namespace": "CWAgent",
                        "append_dimensions": {
                            "InstanceId": "${aws:InstanceId}"
                        },
                        "metrics_collected": {
                            "mem": {
                                "measurement": [
                                    "used_percent"
                                ]
                            }
                        }
                    }
                }
              mode: "000644"
              owner: "root"
              group: "root"
            "/root/install-sw.sh":
              content: !Sub |
                #!/bin/bash
                mkdir -p /tmp/cfn
                cd /tmp/cfn

                # Update OS
                apt-get update -q
                apt-get upgrade -q -y
                apt-get autoremove -q -y

                # CloudWatch agent: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/install-CloudWatch-Agent-commandline-fleet.html#download-CloudWatch-Agent-on-EC2-Instance-commandline-fleet
                if (arch | grep -q x86); then
                  curl -s -L -O https://amazoncloudwatch-agent.s3.amazonaws.com/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb
                else
                  curl -s -L -O https://amazoncloudwatch-agent.s3.amazonaws.com/ubuntu/arm64/latest/amazon-cloudwatch-agent.deb
                fi
                apt-get install -q -y ./amazon-cloudwatch-agent.deb
                /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/bin/config.json -s
                systemctl enable --now amazon-cloudwatch-agent

                # Webmin: https://webmin.com/download/
                export webmin="${installWebmin}"
                case $webmin in
                  Yes)
                    cd /tmp/cfn
                    curl -s -L -O https://raw.githubusercontent.com/webmin/webmin/master/setup-repos.sh
                    echo 'Y' | sh ./setup-repos.sh -f
                    apt-get install -q -y webmin --install-recommends
                    ;;
                esac

                # USB and GPU driver DKMS
                apt-get update
                apt-get install -q -y dkms

                # Kernel headers for GPU and USB remotization
                apt-get install -q -y linux-headers-aws
                apt-get install -q -y linux-modules-extra-aws
                apt-get install -q -y usbutils
                # AWS CLI: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html
                apt-get remove -q -y awscli
                sudo snap install aws-cli --classic
                if [ -e /snap/bin/aws ]; then
                  rm -f /home/ubuntu/update-awscli
                else
                  /home/ubuntu/update-awscli
                fi
                echo "export AWS_CLI_AUTO_PROMPT=on-partial" >> /home/ubuntu/.bashrc

                # Certbot: https://eff-certbot.readthedocs.io/en/stable/install.html#snap-recommended
                sudo snap install certbot --classic
                ln -s /snap/bin/certbot /usr/bin/certbot
                sudo snap set certbot trust-plugin-with-root=ok
                sudo snap install certbot-dns-route53

                rm -f ${!0}
              mode: "000740"
              owner: "root"
              group: "root"
          commands:
            install:
              command: "/root/install-sw.sh >> /var/log/install-sw.log 2>&1"
              ignoreErrors: "true"
        00_dcv_install:
          files:
            "/root/install-dcv.sh":
              content: !Sub |
                #!/bin/bash
                mkdir -p /tmp/cfn
                cd /tmp/cfn

                # Update OS
                apt-get update -q
                apt-get upgrade -q -y

                # DCV prereq: https://docs.aws.amazon.com/dcv/latest/adminguide/setting-up-installing-linux-prereq.html
                apt-get install -q -y ubuntu-desktop-minimal
                apt-get install -q -y gdm3
                apt-get install -q -y amazon-ec2-utils

                # Disable the Wayland protocol: https://docs.aws.amazon.com/dcv/latest/adminguide/setting-up-installing-linux-prereq.html#linux-prereq-wayland
                sed -i '/^\[daemon\]/a WaylandEnable=false' /etc/gdm3/custom.conf

                # resolve "/var/lib/dpkg/info/nice-dcv-server.postinst: 8: dpkg-architecture: not found" when installing dcv-server
                apt-get install -q -y dpkg-dev

                # Microphone redirection: https://docs.aws.amazon.com/dcv/latest/adminguide/setting-up-installing-linux-server.html
                apt-get install -q -y pulseaudio-utils
                apt-get install -q -y gnome-tweaks gnome-shell-extension-ubuntu-dock
                apt-get install -q -y gnome-shell-extension-manager

                # DCV: https://docs.aws.amazon.com/dcv/latest/adminguide/setting-up-installing-linux-server.html
                curl -s -L -O https://d1uj6qtbmh3dt5.cloudfront.net/NICE-GPG-KEY
                gpg --import NICE-GPG-KEY
                OS_VERSION=$(. /etc/os-release;echo $VERSION_ID | sed -e 's/\.//g')
                curl -s -L -O https://d1uj6qtbmh3dt5.cloudfront.net/nice-dcv-ubuntu$OS_VERSION-$(arch).tgz
                tar -xvzf nice-dcv-ubuntu*.tgz && cd nice-dcv-*-$(arch)
                apt-get install -q -y ./nice-dcv-server_*.deb
                apt-get install -q -y ./nice-dcv-web-viewer_*.deb
                usermod -aG video dcv
                apt-get install -q -y ./nice-xdcv_*.deb

                # Printer redirection: https://docs.aws.amazon.com/dcv/latest/adminguide/manage-printer.html
                apt-get install -q -y cups
                GROUP=$(cat /etc/cups/cups-files.conf | grep -oP "SystemGroup\s\K\w+")
                usermod -a -G $GROUP dcv
                systemctl enable cups

                # QUIC: https://docs.aws.amazon.com/dcv/latest/adminguide/enable-quic.html
                cp /etc/dcv/dcv.conf /etc/dcv/dcv.conf."`date +"%Y-%m-%d"`"
                sed -i "s/^#enable-quic-frontend=true/enable-quic-frontend=true/g" /etc/dcv/dcv.conf

                # Higher web client max resolution: https://docs.aws.amazon.com/dcv/latest/adminguide/config-param-ref.html
                sed -i "/^\[display/a web-client-max-head-resolution=(4096, 2160)" /etc/dcv/dcv.conf
                # Console session support
                sed -i "/^\[session-management\/automatic-console-session/a owner=\"ubuntu\"\nstorage-root=\"%home%\"" /etc/dcv/dcv.conf

                # Disable reporting : https://wiki.ubuntu.com/Apport
                sed -i "s/enabled=1/enable=0/g" /etc/default/apport
                apt-get remove -q -y ubuntu-report whoopsie apport
                apt-get autoremove -q -y

                rm -f ${!0}
              mode: "000740"
              owner: "root"
              group: "root"
            "/home/ubuntu/.gnomerc":
              content: |
                export XDG_CURRENT_DESKTOP=ubuntu:GNOME
                export GNOME_SHELL_SESSION_MODE=ubuntu
                export XDG_DATA_DIRS=/usr/share/gnome:/usr/local/share:/usr/share:/var/lib/snapd/desktop
              mode: "000644"
              owner: "ubuntu"
              group: "ubuntu"
          commands:
            install:
              command: "/root/install-dcv.sh > /var/log/install-dcv.log 2>&1"
              ignoreErrors: "true"
        10_nextcloud_install:
          files:
            "/root/install-nextcloud.sh":
              content: !Sub |
                #!/bin/bash
                mkdir -p /tmp/cfn
                cd /tmp/cfn

                export PHP="${phpVersion}"
                export PHP_VERSION=`echo ${phpVersion} | cut -c 4-7`

                # Resolve imagick no SVG support security warning
                apt-get install -q -y libmagickcore-*-extra

                # PHP from Ondrej repo: https://deb.sury.org/
                apt-get install -q -y ca-certificates apt-transport-https software-properties-common lsb-release
                add-apt-repository -y ppa:ondrej/php
                add-apt-repository -y ppa:ondrej/apache2

                # PHP and Apache install
                apt-get install -q -y ${phpVersion} ${phpVersion}-{common,fpm,opcache,apcu,cgi} apache2 libapache2-mod-fcgid
                # https://docs.nextcloud.com/server/latest/admin_manual/installation/php_configuration.html
                apt-get install -q -y ${phpVersion}-{xml,xmlrpc,xsl,soap,ldap,zip,bz2,intl,curl,mbstring,bcmath,imagick,gd}
                apt-get install -q -y ${phpVersion}-{memcached,redis,mysql}
                apt-get install -q -y ${phpVersion}-{igbinary,msgpack,zstd,lz4,bz2}
                apt-get install -q -y ${phpVersion}-{smbclient,gmp}
                apt-get install -q -y ${phpVersion}-ldap

                # Redis for caching and session state
                apt-get install -q -y redis-server
                systemctl enable --now redis-server
                # Enable unix socket
                sed -i "/unixsocketperm/a unixsocket \/var\/run\/redis\/redis-server.sock\nunixsocketperm 770" /etc/redis/redis.conf
                usermod -a -G redis www-data
                systemctl restart redis-server
                # https://docs.nextcloud.com/server/19/admin_manual/configuration_server/caching_configuration.html#id2
                sed -i "/^extension/a redis.session.locking_enabled=1\nredis.session.lock_retries=-1\nredis.session.lock_wait_time=10000\n" /etc/php/$PHP_VERSION/mods-available/redis.ini

                # PHP-FPM ini
                cp /etc/php/$PHP_VERSION/fpm/php.ini /etc/php/$PHP_VERSION/fpm/php.ini."`date +"%Y-%m-%d"`"
                # https://www.php.net/manual/en/opcache.configuration.php
                              
                sed -i "s/^opcache.enable_cli/;&/" /etc/php/$PHP_VERSION/fpm/php.ini
                sed -i "/^;opcache.enable_cli/a opcache.enable_cli=1" /etc/php/$PHP_VERSION/fpm/php.ini

                sed -i "s/^output_buffering/;&/" /etc/php/$PHP_VERSION/fpm/php.ini
                sed -i "/^;output_buffering/a output_buffering=Off" /etc/php/$PHP_VERSION/fpm/php.ini

                sed -i 's/memory_limit =.*/memory_limit = 1024M/' /etc/php/$PHP_VERSION/fpm/php.ini

                sed -i 's/upload_max_filesize =.*/upload_max_filesize = 25G/' /etc/php/$PHP_VERSION/fpm/php.ini
                sed -i 's/post_max_size =.*/post_max_size = 25G/' /etc/php/$PHP_VERSION/fpm/php.ini

                # https://docs.nextcloud.com/server/latest/admin_manual/configuration_files/big_file_upload_configuration.html
                sed -i "s/^max_input_time/;&/" /etc/php/$PHP_VERSION/fpm/php.ini
                sed -i "/^;max_input_time/a max_input_time=3600" /etc/php/$PHP_VERSION/fpm/php.ini                

                sed -i "s/^max_execution_time/;&/" /etc/php/$PHP_VERSION/fpm/php.ini
                sed -i "/^;max_execution_time/a max_execution_time=3600" /etc/php/$PHP_VERSION/fpm/php.ini   

                # https://docs.nextcloud.com/server/latest/admin_manual/installation/server_tuning.html#jit
                sed -i "s/^opcache.jit=/;&/" /etc/php/$PHP_VERSION/mods-available/opcache.ini
                sed -i "/^;opcache.jit=/a opcache.jit=1255\nopcache.jit_buffer_size=128M\nopcache.interned_strings_buffer=16\nopcache.max_accelerated_files=10000\nopcache.memory_consumption=128\nopcache.save_comments=1\nopcache.revalidate_freq=1" /etc/php/$PHP_VERSION/mods-available/opcache.ini

                # https://docs.nextcloud.com/server/20/admin_manual/configuration_server/caching_configuration.html?highlight=memcache#id1
                sed -i "/^extension/a apc.enable_cli=1" /etc/php/$PHP_VERSION/mods-available/apcu.ini

                # https://www.php.net/manual/en/class.sessionhandler.php
                sed -i "s/^session.save_handler/;&/" /etc/php/$PHP_VERSION/fpm/php.ini
                sed -i "/^;session.save_handler/a session.save_handler = redis" /etc/php/$PHP_VERSION/fpm/php.ini
                sed -i "s/^session.save_path/;&/" /etc/php/$PHP_VERSION/fpm/php.ini
                sed -i '/^;session.save_path/a session.save_path = "tcp://127.0.0.1:6379"' /etc/php/$PHP_VERSION/fpm/php.ini

                # PHP CLI ini
                cp /etc/php/$PHP_VERSION/cli/php.ini /etc/php/$PHP_VERSION/cli/php.ini."`date +"%Y-%m-%d"`"
                cp /etc/php/$PHP_VERSION/fpm/php.ini /etc/php/$PHP_VERSION/cli/php.ini

                # php-fpm only: https://www.php.net/manual/en/opcache.configuration.php#ini.opcache.file-cache
                mkdir -p /var/www/.opcache
                chown www-data:www-data /var/www/.opcache
                sed -i 's/;opcache.file_cache=.*/opcache.file_cache=\/var\/www\/.opcache/' /etc/php/$PHP_VERSION/fpm/php.ini

                # tune php-fpm for 8 GB RAM: https://docs.nextcloud.com/server/latest/admin_manual/installation/server_tuning.html#tune-php-fpm
                # PHP-FPM Process Calculator at https://spot13.com/pmcalculator/
                sed -i "s/^pm.max_children/;&/" /etc/php/$PHP_VERSION/fpm/pool.d/www.conf
                sed -i "/^;pm.max_children/a pm.max_children = 230" /etc/php/$PHP_VERSION/fpm/pool.d/www.conf
                sed -i "s/^pm.start_servers/;&/" /etc/php/$PHP_VERSION/fpm/pool.d/www.conf
                sed -i "/^;pm.start_servers/a pm.start_servers = 50" /etc/php/$PHP_VERSION/fpm/pool.d/www.conf
                sed -i "s/^pm.min_spare_servers/;&/" /etc/php/$PHP_VERSION/fpm/pool.d/www.conf
                sed -i "/^;pm.min_spare_servers/a pm.min_spare_servers = 50" /etc/php/$PHP_VERSION/fpm/pool.d/www.conf
                sed -i "s/^pm.max_spare_servers/;&/" /etc/php/$PHP_VERSION/fpm/pool.d/www.conf
                sed -i "/^;pm.max_spare_servers/a pm.max_spare_servers = 150" /etc/php/$PHP_VERSION/fpm/pool.d/www.conf

                systemctl enable ${phpVersion}-fpm
                systemctl restart ${phpVersion}-fpm

                # Certbot: Use Snap version
                # apt-get install -q -y certbot
                # apt-get install -q -y python3-certbot-apache python3-certbot-dns-route53 python-certbot-dns-route53-doc 

                # Apache MPM event: https://httpd.apache.org/docs/2.4/mod/event.html
                a2dismod ${phpVersion}
                a2dismod mpm_prefork
                a2enmod mpm_event proxy_fcgi setenvif
                a2enconf ${phpVersion}-fpm

                # Enable HTTPS 
                a2enmod ssl
                a2enmod rewrite
                a2enmod http2

                # HTTPS site: for Certbot
                a2ensite default-ssl

                # Enable index.php
                sed -i "s/\bDirectoryIndex\b/& index.php/" /etc/apache2/mods-enabled/dir.conf

                # Change permissions and ownership
                usermod -a -G www-data ubuntu
                chown -R ubuntu:www-data /var/www/html
                chmod -R 2775 /var/www/html
                find /var/www/html -type d -exec sudo chmod 2775 {} \;
                find /var/www/html -type f -exec sudo chmod 0664 {} \;

                # Nextcloud
                a2enmod headers
                a2enmod env
                a2enmod dir
                a2enmod mime

                # https://docs.nextcloud.com/server/29/admin_manual/issues/general_troubleshooting.html#service-discovery
                a2enconf nextcloud
                systemctl enable apache2
                systemctl restart apache2

                # MySQL/MariaDB database
                # https://docs.nextcloud.com/server/20/admin_manual/configuration_database/linux_database_configuration.html#database-read-committed-transaction-isolation-level
                export DB="${databaseOption}"
                case $DB in
                  MySQL)
                    apt-get install -q -y mysql-server
                    # https://docs.nextcloud.com/server/20/admin_manual/configuration_database/mysql_4byte_support.html#
                    cp /etc/mysql/mysql.conf.d/mysqld.cnf /etc/mysql/mysql.conf.d/mysqld.cnf."`date +"%Y-%m-%d"`"
                    sed -i "/^\[mysqld\]/a innodb_file_per_table=1\ntransaction_isolation = READ-COMMITTED" /etc/mysql/mysql.conf.d/mysqld.cnf
                    sed -i "/^#innodb_buffer_pool_size/a innodb_buffer_pool_size = 512M" /etc/mysql/mysql.conf.d/mysqld.cnf
                    systemctl enable --now mysql
                    ;;
                  MariaDB)
                    apt-get install -q -y mariadb-server
                    # https://docs.nextcloud.com/server/20/admin_manual/configuration_database/mysql_4byte_support.html#mariadb-10-3-or-later
                    cp /etc/mysql/mariadb.conf.d/50-server.cnf /etc/mysql/mariadb.conf.d/50-server.cnf."`date +"%Y-%m-%d"`"
                    sed -i "/^\[mysqld\]/a innodb_file_per_table=1\ntransaction_isolation = READ-COMMITTED" /etc/mysql/mariadb.conf.d/50-server.cnf
                    sed -i "/^#innodb_buffer_pool_size/a innodb_buffer_pool_size = 512M" /etc/mysql/mariadb.conf.d/50-server.cnf
                    systemctl enable --now mariadb
                    ;;
                esac

                # Nextcloud files
                cd /tmp
                curl -s -L -O https://nextcloud.com/nextcloud.asc
                gpg --import nextcloud.asc

                curl -s -L -O https://download.nextcloud.com/server/releases/latest.zip
                curl -s -L -O https://download.nextcloud.com/server/releases/latest.zip.asc
                gpg --verify latest.zip.asc

                unzip -q /tmp/latest.zip
                rsync -r /tmp/nextcloud/ /var/www/html/

                # Preconfigured config.php
                cp /root/nextcloud/config.php /var/www/html/config/config.php
                chown -R www-data:www-data /var/www/html/

                # Generate random Nextcloud and MySQL/MariaDB password
                export rndPassword=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1`
                echo "Password = $rndPassword" >> /root/.nextcloud-credentials

                # Prepare database
                sudo mysql -u root -e "CREATE USER 'nextcloud'@'localhost' IDENTIFIED BY '$rndPassword';
                CREATE DATABASE IF NOT EXISTS nextcloud CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
                GRANT ALL PRIVILEGES ON nextcloud.* TO 'nextcloud'@'localhost';
                FLUSH PRIVILEGES;"

                # Install Nextcloud: https://docs.nextcloud.com/server/latest/admin_manual/configuration_server/occ_command.html#command-line-installation-label
                cd /var/www/html/
                sudo -u www-data php occ  maintenance:install \
                 --database='mysql' --database-name='nextcloud' \
                 --database-user='nextcloud' --database-pass="$rndPassword" \
                 --admin-user='${adminUsername}' --admin-pass="$rndPassword"

                # nextcloud.occ
                echo "alias nextcloud.occ='sudo -u www-data php /var/www/html/occ'" >> ~/.bashrc
                echo "alias nextcloud.occ='sudo -u www-data php /var/www/html/occ'" >> /home/ubuntu/.bashrc

                # Allow ALL as trusted_domains: https://docs.nextcloud.com/server/stable/admin_manual/configuration_server/config_sample_php_parameters.html#trusted-domains
                sudo -u www-data php occ config:system:set "trusted_domains" 1 --value=*

                # phpinfo troubleshooting: https://docs.nextcloud.com/server/stable/admin_manual/issues/general_troubleshooting.html
                sudo -u www-data php occ config:app:set --value=yes serverinfo phpinfo

                # Disable default apps
                sudo -u www-data php occ app:disable dashboard
                sudo -u www-data php occ app:disable photos
                sudo -u www-data php occ app:disable firstrunwizard
                sudo -u www-data php occ app:disable weather_status

                # Enable apps
                sudo -u www-data php occ app:enable files_external
                sudo -u www-data php occ app:install user_saml
                sudo -u www-data php occ app:enable user_ldap

                # Mount S3 as external storage?
                export S3Bucket="${externalS3Bucket}"
                if [ -n "$S3Bucket" ]; then
                  sudo -u www-data php /var/www/html/occ files_external:create \
                    "AmazonS3-${externalS3Bucket}"  "amazons3" "amazons3::accesskey" \
                    -c key="${userAccessKey}" -c secret="${userAccessKey.SecretAccessKey}" \
                    -c region=${externalS3BucketRegion} -c bucket="${externalS3Bucket}" -c storageClass="${externalS3BucketStorageClass}"
                fi

                # May fix large file transfer failure for S3 external storage. Best option is to use larger instance size
                # https://github.com/nextcloud/server/issues/24390 https://help.nextcloud.com/t/s3-random-storage-problem-on-large-files/72897/4
                # sed -i "s/524288000;/104857600;/g" /var/www/html/lib/private/Files/ObjectStore/S3ConnectionTrait.php

                # sendmail
                apt-get install -q -y sendmail

                # jq: for parsing /var/www/html/data/nextcloud.log
                apt-get install -q -y jq

                # https://docs.nextcloud.com/server/latest/admin_manual/configuration_server/background_jobs_configuration.html#cron-jobs
                crontab -u www-data /root/nextcloud/crontab-www-data

                rm -f ${!0}
              mode: "000740"
              owner: "root"
              group: "root"
            "/etc/apache2/conf-available/nextcloud.conf": # https://docs.nextcloud.com/server/stable/admin_manual/installation/source_installation.html#apache-configuration-label
              content: |
                <Directory /var/www/>
                  Require all granted
                  AllowOverride All
                  Options FollowSymLinks MultiViews

                  <IfModule mod_dav.c>
                    Dav off
                  </IfModule>
                </Directory>
              mode: "000644"
              owner: "root"
              group: "root"
            "/root/nextcloud/config.php":
              # https://docs.nextcloud.com/server/latest/admin_manual/configuration_files/files_locking_transactional.html
              # https://docs.nextcloud.com/server/latest/admin_manual/configuration_files/primary_storage.html
              # https://docs.nextcloud.com/server/latest/admin_manual/configuration_files/default_files_configuration.html
              # https://docs.nextcloud.com/server/latest/admin_manual/configuration_server/config_sample_php_parameters.html
              # https://docs.nextcloud.com/server/latest/admin_manual/configuration_files/default_files_configuration.html
              content: !Sub
                - |
                  <?php

                  $CONFIG = array(
                    'trusted_domains' =>
                    array (
                      0 => 'localhost',
                      1 => '*',
                    ),
                    'trusted_proxies' =>
                    array (
                      0 => '10.0.0.0/8',
                      1 => '172.16.0.0/12',
                      2 => '192.168.0.0/16',
                    ),
                    'default_phone_region' => 'SG',
                    'maintenance_window_start' => 1,
                    'memcache.local' => '\OC\Memcache\APCu',
                    'memcache.distributed' => '\OC\Memcache\Redis',
                    'memcache.locking' => '\OC\Memcache\Redis',
                    'redis' => [
                         'host' => '/var/run/redis/redis-server.sock',
                         'port' => 0,
                         'timeout' => 0.0,
                    ],
                    'mysql.utf8mb4' => true,
                    'htaccess.RewriteBase' => '/',
                    'defaultapp' => 'files',
                    'skeletondirectory' => '', # set to '/var/www/html/core/skeleton' to include skeleton files               
                    'objectstore' => array(
                      'class' => 'OC\\Files\\ObjectStore\\S3',
                      'arguments' => array(
                        'bucket' => '${bucketName}',
                        'region' => '${AWS::Region}',
                        'hostname' => 's3.${AWS::Region}.amazonaws.com',
                        'storageClass' => '${s3StorageClass}',
                        'uploadPartSize' => '524288000',
                        'verify_bucket_exists' => false,
                        'use_ssl' => true
                      ),
                    ),
                  );
                - bucketName:
                    !If [
                      noS3BucketLogging,
                      !Ref s3Bucket,
                      !Ref s3BucketWithLogging,
                    ]
              mode: "000640"
              owner: "root"
              group: "root"
            "/root/nextcloud/crontab-www-data":
              content: |
                */5  *  *  *  * php -f /var/www/html/cron.php
              mode: "000640"
              owner: "root"
              group: "root"
            "/root/.nextcloud-credentials":
              content: !Sub |
                IAM User: ${iamUser}
                ACCESS_KEY = ${userAccessKey}
                SECRET_ACCESS_KEY = ${userAccessKey.SecretAccessKey}

                Database User: nextcloud

              mode: "000400"
              owner: "root"
              group: "root"
          commands:
            install:
              command: "/root/install-nextcloud.sh > /var/log/install-nextcloud.log 2>&1"
              ignoreErrors: "true"
    Properties:
      ImageId: # https://ubuntu.com/server/docs/cloud-images/amazon-ec2 https://ubuntu.com/blog/ubuntu-pro-is-now-part-of-the-aws-ec2-console
        !If [
          useUbuntu2404x86,
          "{{resolve:ssm:/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id}}",
          !If [
            useUbuntu2404arm64,
            "{{resolve:ssm:/aws/service/canonical/ubuntu/server/24.04/stable/current/arm64/hvm/ebs-gp3/ami-id}}",
            !If [
              useUbuntu2204x86,
              "{{resolve:ssm:/aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id}}",
              !If [
                useUbuntu2204arm64,
                "{{resolve:ssm:/aws/service/canonical/ubuntu/server/22.04/stable/current/arm64/hvm/ebs-gp2/ami-id}}",
                !If [
                  useUbuntuPro2404x86,
                  "{{resolve:ssm:/aws/service/canonical/ubuntu/pro-server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id}}",
                  !If [
                    useUbuntuPro2404arm64,
                    "{{resolve:ssm:/aws/service/canonical/ubuntu/pro-server/24.04/stable/current/arm64/hvm/ebs-gp3/ami-id}}",
                    !If [
                      useUbuntuPro2204x86,
                      "{{resolve:ssm:/aws/service/canonical/ubuntu/pro-server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id}}",
                      "{{resolve:ssm:/aws/service/canonical/ubuntu/pro-server/22.04/stable/current/arm64/hvm/ebs-gp2/ami-id}}",
                    ],
                  ],
                ],
              ],
            ],
          ],
        ]
      InstanceType: !Ref instanceType
      IamInstanceProfile: !Ref instanceProfile
      KeyName: !Ref ec2KeyPair
      SubnetId: !Ref subnetID
      Monitoring: true
      DisableApiTermination: !If [enableProtection, true, false]
      EbsOptimized: true
      SecurityGroupIds:
        - !Ref securityGroup
      BlockDeviceMappings:
        - DeviceName: /dev/sda1
          Ebs:
            VolumeType: !Ref volumeType
            VolumeSize: !Ref volumeSize
            DeleteOnTermination: true
            Encrypted: true
      UserData:
        Fn::Base64: !Sub |
          #!/bin/bash
          mkdir -p /tmp/cfn
          cd /tmp/cfn

          # disable IPv6 during setup
          sysctl -w net.ipv6.conf.all.disable_ipv6=1
          sysctl -w net.ipv6.conf.default.disable_ipv6=1

          # https://stackoverflow.com/questions/33370297/apt-get-update-non-interactive
          export DEBIAN_FRONTEND=noninteractive

          systemctl stop apt-daily.timer apt-daily-upgrade.timer
          apt-get clean all
          apt-get update -q
          apt-get install -q -y procps
          pkill apt
          apt-get install -q -y wget tmux unzip tar curl sed

          # CfN scripts: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-helper-scripts-reference.html
          apt-get install -q -y python3 python3-pip python3-setuptools python3-docutils python3-daemon
          curl -s -L -O https://s3.amazonaws.com/cloudformation-examples/aws-cfn-bootstrap-py3-latest.tar.gz
          tar -xf aws-cfn-bootstrap-py3-latest.tar.gz
          cd aws-cfn-bootstrap-2.0
          python3 setup.py build > /var/log/install-cfn-helper.log 2>&1
          python3 setup.py install >> /var/log/install-cfn-helper.log 2>&1
          cd /tmp/cfn
          export CFN_INIT="python3 /usr/local/bin/cfn-init"

          $CFN_INIT -v --stack ${AWS::StackName} --resource ec2Instance --region ${AWS::Region} -c setup

          # Install desktop environment and DCV?
          export installDCV="${installDCV}"
          case $installDCV in
            Yes)
              $CFN_INIT -v --stack ${AWS::StackName} --resource ec2Instance --region ${AWS::Region} -c dcv_install
              ;;
          esac 

          # Nextcloud
          $CFN_INIT -v --stack ${AWS::StackName} --resource ec2Instance --region ${AWS::Region} -c nextcloud_install

          #
          systemctl set-default multi-user.target
          systemctl daemon-reload
          systemctl enable dcv-post-reboot

          # enable back IPv6
          sysctl -w net.ipv6.conf.all.disable_ipv6=0
          sysctl -w net.ipv6.conf.default.disable_ipv6=0

          sleep 1 && reboot
      Tags:
        - Key: Name
          Value: !Ref ec2Name
        - Key: StackName
          Value: !Ref AWS::StackName
        - Key: StackId
          Value: !Ref AWS::StackId
        - Key: GitHub
          Value: https://github.com/aws-samples/nextcloud-server

  elasticIP:
    Condition: useElasticIP
    Type: AWS::EC2::EIP
    Properties:
      Domain: vpc
      NetworkBorderGroup: !Ref AWS::Region
      InstanceId: !Ref ec2Instance
      Tags:
        - Key: StackName
          Value: !Ref AWS::StackName
        - Key: StackId
          Value: !Ref AWS::StackId
        - Key: Name
          Value: !Sub
            - "${AWS::StackName}-elasticIP-${UID}"
            - UID:
                !Select [
                  3,
                  !Split ["-", !Select [2, !Split ["/", !Ref AWS::StackId]]],
                ]
        - Key: GitHub
          Value: https://github.com/aws-samples/nextcloud-server

  backupPlan:
    Type: AWS::Backup::BackupPlan
    Condition: createBackup
    Properties:
      BackupPlan:
        BackupPlanName: !Sub
          - "${AWS::StackName}-backupPlan-${UID}"
          - UID:
              !Select [
                3,
                !Split ["-", !Select [2, !Split ["/", !Ref AWS::StackId]]],
              ]
        BackupPlanRule:
          - RuleName: !Sub
              - "${AWS::StackName}-backupRule-${UID}"
              - UID:
                  !Select [
                    3,
                    !Split ["-", !Select [2, !Split ["/", !Ref AWS::StackId]]],
                  ]
            TargetBackupVault: !Ref backupVault
            ScheduleExpression: !Ref scheduleExpression
            ScheduleExpressionTimezone: !Ref scheduleExpressionTimezone
            Lifecycle:
              DeleteAfterDays: !Ref deleteAfterDays
      BackupPlanTags:
        {
          "StackName": !Ref AWS::StackName,
          "StackId": !Ref AWS::StackId,
          "GitHub": "https://github.com/aws-samples/nextcloud-server",
        }

  backupVault:
    Type: AWS::Backup::BackupVault
    Condition: createBackup
    UpdateReplacePolicy: Delete
    Properties:
      BackupVaultName: !Sub
        - "${AWS::StackName}-backupVault-${UID}"
        - UID:
            !Select [
              3,
              !Split ["-", !Select [2, !Split ["/", !Ref AWS::StackId]]],
            ]
      BackupVaultTags:
        {
          "StackName": !Ref AWS::StackName,
          "StackId": !Ref AWS::StackId,
          "GitHub": "https://github.com/aws-samples/nextcloud-server",
        }

  backupSelection:
    Type: AWS::Backup::BackupSelection
    Condition: createBackup
    Properties:
      BackupPlanId: !Ref backupPlan
      BackupSelection:
        IamRoleArn: !GetAtt backupRestoreRole.Arn
        Resources:
          - !If
            - backupS3
            - !If [
                noS3BucketLogging,
                !GetAtt s3Bucket.Arn,
                !GetAtt s3BucketWithLogging.Arn,
              ]
            - !Ref AWS::NoValue
          - !If
            - backupEC2
            - !Sub "arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:instance/${ec2Instance}"
            - !Ref AWS::NoValue
          - !If
            - backupExternalStorage
            - !Sub "arn:${AWS::Partition}:s3:::${externalS3Bucket}"
            - !Ref AWS::NoValue
        SelectionName: !Sub
          - "${AWS::StackName}-backupSelection-${UID}"
          - UID:
              !Select [
                3,
                !Split ["-", !Select [2, !Split ["/", !Ref AWS::StackId]]],
              ]

  backupRestoreRole:
    Type: AWS::IAM::Role
    Condition: createBackup
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: backup.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: restore-EC2-instance-profile
          PolicyDocument: # https://docs.aws.amazon.com/aws-backup/latest/devguide/restoring-ec2.html
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                  - iam:PassRole
                Resource: !GetAtt instanceIamRole.Arn
      ManagedPolicyArns:
        - !Sub "arn:${AWS::Partition}:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
        - !Sub "arn:${AWS::Partition}:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores"
        - !Sub "arn:${AWS::Partition}:iam::aws:policy/AWSBackupServiceRolePolicyForS3Backup"
        - !Sub "arn:${AWS::Partition}:iam::aws:policy/AWSBackupServiceRolePolicyForS3Restore"
      Tags:
        - Key: StackName
          Value: !Ref AWS::StackName
        - Key: StackId
          Value: !Ref AWS::StackId
        - Key: GitHub
          Value: https://github.com/aws-samples/nextcloud-server

Outputs:
  SetPasswordCmd:
    Description: Set Nextcloud admin password command
    Value: !Sub "sudo -u www-data php /var/www/html/occ user:resetpassword ${adminUsername}"

  EC2console:
    Description: EC2 console
    Value: !Sub "https://${AWS::Region}.console.aws.amazon.com/ec2/home?region=${AWS::Region}#Instances:search=${ec2Instance}"

  EC2instanceConnect:
    Condition: createSgEIC
    Description: EC2 Instance Connect
    Value: !Sub "https://${AWS::Region}.console.aws.amazon.com/ec2-instance-connect/ssh?connType=standard&instanceId=${ec2Instance}&osUser=ubuntu&sshPort=22#/"

  EC2serialConsole:
    Description: EC2 Serial Console
    Value: !Sub "https://${AWS::Region}.console.aws.amazon.com/ec2-instance-connect/ssh?connType=serial&instanceId=${ec2Instance}&serialPort=0#/"

  SSMsessionManager:
    Condition: noDCV
    Description: SSM Session Manager
    Value: !Sub "https://${AWS::Region}.console.aws.amazon.com/systems-manager/session-manager/${ec2Instance}"

  SSMsessionManagerDCV:
    Condition: installDCV
    Description: SSM Session Manager ("sudo passwd ubuntu" to set password for DCV login)
    Value: !Sub "https://${AWS::Region}.console.aws.amazon.com/systems-manager/session-manager/${ec2Instance}"

  DCVwebConsole:
    Condition: installDCV
    Description: DCV web browser client (login as ubuntu)
    Value:
      !If [
        displayPublicIP,
        !Sub "https://${ec2Instance.PublicIp}:8443",
        !Sub "https://${ec2Instance.PrivateIp}:8443",
      ]

  WebUrl:
    Description: Website
    Value:
      !If [
        displayPublicIP,
        !Sub "https://${ec2Instance.PublicIp}",
        !Sub "https://${ec2Instance.PrivateIp}",
      ]

  WebminUrl:
    Condition: installWebmin
    Description: Webmin (set root password and login as root)
    Value:
      !If [
        displayPublicIP,
        !Sub "https://${ec2Instance.PublicIp}:10000",
        !Sub "https://${ec2Instance.PrivateIp}:10000",
      ]

  NextcloudLogUrl:
    Description: Cloudwatch log for nextcloud.log
    Value: !Sub "https://${AWS::Region}.console.aws.amazon.com/cloudwatch/home?region=${AWS::Region}#logsV2:log-groups/log-group/nextcloud.log/log-events/${ec2Instance}"
