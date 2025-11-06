# Отчёт по результатам анализа Kubernetes Audit Log

## Подозрительные события

1. Доступ к секретам:
   - Кто: system:apiserver
   - Где: ns=—, ресурс=secrets, имя=—
   - Почему подозрительно: попытка чтения secrets.

2. Привилегированные поды:
   - Не обнаружено.

3. Использование kubectl exec в чужом поде:
   - Не обнаружено.

4. Создание RoleBinding с правами cluster-admin:
   - Кто: kubernetes-admin
   - Где: ns=—, ресурс=clusterrolebindings, имя=kubeadm:cluster-admins
   - К чему привело: эскалация привилегий.

5. Удаление audit-policy.yaml:
   - Не обнаружено.

## Вывод

- Всего подозрительных событий: 7
- Статистика: {"secrets": 6, "privileged-pod": 0, "cross-exec": 0, "cluster-admin": 1, "audit-policy-delete": 0}
- Основные ошибки RBAC: слишком широкие права на pods, secrets и RoleBinding.

### Активность пользователей:
- minikube-user: 4
- system:apiserver: 2
- kubernetes-admin: 1