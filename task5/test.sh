# проверка
kubectl get networkpolicies

# разрешенные
kubectl run test-frontend --rm -i -t --image=alpine -- sh
/ # wget -qO- --timeout=2 http://back-end-api-app

kubectl run test-admin --rm -i -t --image=alpine -- sh
/ # wget -qO- --timeout=2 http://admin-back-end-api-app

# запрещенные
kubectl run test-blocked --rm -i -t --image=alpine -- sh
/ # wget -qO- --timeout=2 http://admin-back-end-api-app
