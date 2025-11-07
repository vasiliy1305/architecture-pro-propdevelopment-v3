declare -A USERS
USERS=(
  ["admin-user"]="devops"
  ["viewer-user"]="developers"
  ["editor-user"]="operations"
  ["security-user"]="security"
)

CA_CERT=~/.minikube/ca.crt
CA_KEY=~/.minikube/ca.key
if [[ ! -f "$CA_CERT" || ! -f "$CA_KEY" ]]; then
  echo "Не найдены файлы CA Minikube ($CA_CERT / $CA_KEY)"
  echo "Запусти кластер: minikube start"
  exit 1
fi

for USER in "${!USERS[@]}"; do
  ORG=${USERS[$USER]}
  echo "🔹 Создаю пользователя: $USER (группа: $ORG)"
  openssl genrsa -out ${USER}.key 2048
  openssl req -new -key ${USER}.key -out ${USER}.csr -subj "/CN=${USER}/O=${ORG}"
  openssl x509 -req -in ${USER}.csr -CA $CA_CERT -CAkey $CA_KEY -CAcreateserial -out ${USER}.crt -days 365
  kubectl config set-credentials ${USER} \
    --client-certificate=${USER}.crt \
    --client-key=${USER}.key
  
  echo "Пользователь ${USER} создан и добавлен в kubeconfig"
done

echo "Все пользователи успешно созданы!"
