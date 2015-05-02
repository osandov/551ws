#!/bin/sh

STATUS_CODES=()

STATUS_CODES[400]="Bad Request"
STATUS_CODES[403]="Forbidden"
STATUS_CODES[404]="Not Found"
STATUS_CODES[500]="Internal Server Error"
STATUS_CODES[501]="Not Implemented"

for STATUS_CODE in "${!STATUS_CODES[@]}"; do
	MESSAGE="${STATUS_CODES[$STATUS_CODE]}"
	cat > www/"${STATUS_CODE}".html << EOF
<!DOCTYPE html>
<html>
	<head>
		<title>551ws $MESSAGE</title>
	</head>
	<body>
		<h1>$STATUS_CODE $MESSAGE</h1>
	</body>
</html>
EOF
done
