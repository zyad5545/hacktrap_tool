#!/bin/bash
COUNT=${1:-50}
URL="http://localhost:5000/api/attack"

usernames=(admin root test guest)
passwords=(1234 123456 password admin123 qwerty)

for i in $(seq 1 $COUNT); do
  user=${usernames[$((RANDOM % ${#usernames[@]}))]}
  pass=${passwords[$((RANDOM % ${#passwords[@]}))]}
  data="{\"type\":\"brute_force\",\"source_ip\":\"172.19.0.$((RANDOM%254+1))\",\"details\":\"Invalid login attempt ${user}/${pass}\"}"
  curl -s -X POST -H "Content-Type: application/json" -d "$data" "$URL" >/dev/null &
  sleep 0.05
done

echo "تم إرسال $COUNT محاولة brute-force إلى $URL"