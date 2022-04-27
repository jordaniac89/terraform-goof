package rules

deny[msg] {
	resource := input.resource.aws_redshift_cluster[name]
	not resource.tags.owner
	msg := {
		# Mandatory fields
		"publicId": "S3-TAG",
		"title": "Default title",
		"severity": "low",
		"msg": sprintf("input.resource.aws_redshift_cluster[deny].tags", [name]), # must be the JSON path to the resource field that triggered the deny rule
		# Optional fields
		"issue": "",
		"impact": "",
		"remediation": "",
		"references": [],
	}
}
