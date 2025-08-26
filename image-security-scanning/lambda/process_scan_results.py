import json
import boto3
import os
import logging
from datetime import datetime

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
ecr_client = boto3.client('ecr')
sns_client = boto3.client('sns')

def handler(event, context):
    """
    Lambda function to process ECR image scan results and send alerts
    for vulnerabilities that exceed defined thresholds.
    """
    
    try:
        # Extract event details
        detail = event.get('detail', {})
        repository_name = detail.get('repository-name')
        image_tag = detail.get('image-tags', ['latest'])[0]
        scan_status = detail.get('scan-status')
        
        logger.info(f"Processing scan results for {repository_name}:{image_tag}")
        
        # Get environment variables
        critical_threshold = int(os.environ.get('CRITICAL_THRESHOLD', 0))
        high_threshold = int(os.environ.get('HIGH_THRESHOLD', 5))
        sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')
        
        if scan_status != 'COMPLETE':
            logger.warning(f"Scan status is {scan_status}, skipping processing")
            return {
                'statusCode': 200,
                'body': json.dumps(f'Scan status: {scan_status}')
            }
        
        # Get scan findings
        response = ecr_client.describe_image_scan_findings(
            repositoryName=repository_name,
            imageId={'imageTag': image_tag}
        )
        
        findings = response.get('imageScanFindings', {})
        finding_counts = findings.get('findingCounts', {})
        
        # Extract vulnerability counts
        critical_count = finding_counts.get('CRITICAL', 0)
        high_count = finding_counts.get('HIGH', 0)
        medium_count = finding_counts.get('MEDIUM', 0)
        low_count = finding_counts.get('LOW', 0)
        
        logger.info(f"Vulnerability counts - Critical: {critical_count}, High: {high_count}, Medium: {medium_count}, Low: {low_count}")
        
        # Check thresholds
        threshold_exceeded = False
        alert_messages = []
        
        if critical_count > critical_threshold:
            threshold_exceeded = True
            alert_messages.append(f"🚨 CRITICAL: {critical_count} vulnerabilities (threshold: {critical_threshold})")
        
        if high_count > high_threshold:
            threshold_exceeded = True
            alert_messages.append(f"⚠️ HIGH: {high_count} vulnerabilities (threshold: {high_threshold})")
        
        # Generate detailed findings for critical and high vulnerabilities
        critical_high_findings = []
        for finding in findings.get('findings', []):
            if finding.get('severity') in ['CRITICAL', 'HIGH']:
                critical_high_findings.append({
                    'name': finding.get('name'),
                    'severity': finding.get('severity'),
                    'description': finding.get('description', ''),
                    'uri': finding.get('uri', ''),
                    'attributes': finding.get('attributes', [])
                })
        
        # Prepare scan summary
        scan_summary = {
            'repository': repository_name,
            'image_tag': image_tag,
            'scan_timestamp': datetime.utcnow().isoformat(),
            'vulnerability_counts': {
                'critical': critical_count,
                'high': high_count,
                'medium': medium_count,
                'low': low_count
            },
            'thresholds': {
                'critical': critical_threshold,
                'high': high_threshold
            },
            'threshold_exceeded': threshold_exceeded,
            'critical_high_findings': critical_high_findings[:10]  # Limit to first 10 findings
        }
        
        # Send SNS notification if thresholds exceeded
        if threshold_exceeded and sns_topic_arn:
            send_security_alert(sns_topic_arn, scan_summary, alert_messages)
        
        # Log results
        if threshold_exceeded:
            logger.error(f"Vulnerability thresholds exceeded for {repository_name}:{image_tag}")
        else:
            logger.info(f"Vulnerability scan passed for {repository_name}:{image_tag}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Scan results processed successfully',
                'scan_summary': scan_summary
            })
        }
        
    except Exception as e:
        logger.error(f"Error processing scan results: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f'Error: {str(e)}')
        }

def send_security_alert(sns_topic_arn, scan_summary, alert_messages):
    """
    Send security alert via SNS when vulnerability thresholds are exceeded.
    """
    
    try:
        repository = scan_summary['repository']
        image_tag = scan_summary['image_tag']
        vulnerability_counts = scan_summary['vulnerability_counts']
        
        # Create alert message
        subject = f"🚨 Container Security Alert: {repository}:{image_tag}"
        
        message_body = f"""
CONTAINER SECURITY ALERT

Repository: {repository}
Image Tag: {image_tag}
Scan Time: {scan_summary['scan_timestamp']}

VULNERABILITY SUMMARY:
{chr(10).join(alert_messages)}

DETAILED COUNTS:
• Critical: {vulnerability_counts['critical']}
• High: {vulnerability_counts['high']}
• Medium: {vulnerability_counts['medium']}
• Low: {vulnerability_counts['low']}

CRITICAL/HIGH FINDINGS:
"""
        
        # Add detailed findings
        for i, finding in enumerate(scan_summary['critical_high_findings'], 1):
            message_body += f"""
{i}. {finding['name']} ({finding['severity']})
   Description: {finding['description'][:200]}...
   URI: {finding['uri']}
"""
        
        message_body += f"""

ACTION REQUIRED:
1. Review the vulnerability findings in the ECR console
2. Update base images or dependencies to address vulnerabilities
3. Re-scan the image after fixes are applied
4. Contact the security team if exceptions are needed

ECR Console: https://console.aws.amazon.com/ecr/repositories/{repository}
"""
        
        # Send SNS message
        response = sns_client.publish(
            TopicArn=sns_topic_arn,
            Subject=subject,
            Message=message_body,
            MessageAttributes={
                'repository': {
                    'DataType': 'String',
                    'StringValue': repository
                },
                'image_tag': {
                    'DataType': 'String',
                    'StringValue': image_tag
                },
                'severity': {
                    'DataType': 'String',
                    'StringValue': 'HIGH' if vulnerability_counts['critical'] > 0 else 'MEDIUM'
                }
            }
        )
        
        logger.info(f"Security alert sent successfully. MessageId: {response['MessageId']}")
        
    except Exception as e:
        logger.error(f"Failed to send security alert: {str(e)}")
        raise