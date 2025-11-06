
minikube start
kubectl apply -f 01-create-namespace.yaml
kubectl get ns audit-zone --show-labels

---

kubectl apply -f insecure-manifests/
Error from server (Forbidden): error when creating "insecure-manifests/01-privileged-pod.yaml": pods "privileged-pod" is forbidden: violates PodSecurity "restricted:latest": privileged (container "nginx" must not set securityContext.privileged=true), allowPrivilegeEscalation != false (container "nginx" must set securityContext.allowPrivilegeEscalation=false), unrestricted capabilities (container "nginx" must set securityContext.capabilities.drop=["ALL"]), runAsNonRoot != true (pod or container "nginx" must set securityContext.runAsNonRoot=true), seccompProfile (pod or container "nginx" must set securityContext.seccompProfile.type to "RuntimeDefault" or "Localhost")
Error from server (Forbidden): error when creating "insecure-manifests/02-hostpath-pod.yaml": pods "hostpath-pod" is forbidden: violates PodSecurity "restricted:latest": allowPrivilegeEscalation != false (container "nginx" must set securityContext.allowPrivilegeEscalation=false), unrestricted capabilities (container "nginx" must set securityContext.capabilities.drop=["ALL"]), restricted volume types (volume "host-vol" uses restricted volume type "hostPath"), runAsNonRoot != true (pod or container "nginx" must set securityContext.runAsNonRoot=true), seccompProfile (pod or container "nginx" must set securityContext.seccompProfile.type to "RuntimeDefault" or "Localhost")
Error from server (Forbidden): error when creating "insecure-manifests/03-root-user-pod.yaml": pods "root-user-pod" is forbidden: violates PodSecurity "restricted:latest": allowPrivilegeEscalation != false (container "nginx" must set securityContext.allowPrivilegeEscalation=false), unrestricted capabilities (container "nginx" must set securityContext.capabilities.drop=["ALL"]), runAsNonRoot != true (pod or container "nginx" must set securityContext.runAsNonRoot=true), runAsUser=0 (container "nginx" must not set runAsUser=0), seccompProfile (pod or container "nginx" must set securityContext.seccompProfile.type to "RuntimeDefault" or "Localhost")

---

kubectl apply -f secure-manifests/
pod/secure-privileged-pod created
pod/secure-hostpath-pod created
pod/secure-root-user-pod created

kubectl get pods -n audit-zone
NAME                    READY   STATUS    RESTARTS   AGE
secure-hostpath-pod     1/1     Running   0          10s
secure-privileged-pod   1/1     Running   0          10s
secure-root-user-pod    1/1     Running   0          10s

---

kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/release-3.16/deploy/gatekeeper.yaml

kubectl get pods -n gatekeeper-system
NAME                                             READY   STATUS    RESTARTS      AGE
gatekeeper-audit-7684b8c667-5ncvs                1/1     Running   1 (18s ago)   30s
gatekeeper-controller-manager-84c4d85879-8v6rf   1/1     Running   0             30s
gatekeeper-controller-manager-84c4d85879-rk8rl   0/1     Running   0             30s
gatekeeper-controller-manager-84c4d85879-rqb72   1/1     Running   0             30s

---

va@Lenovo:~/projects/architecture-pro-propdevelopment/Task7$ kubectl apply -f gatekeeper/constraint-templates/privileged.yaml
constrainttemplate.templates.gatekeeper.sh/k8sprivileged created
va@Lenovo:~/projects/architecture-pro-propdevelopment/Task7$ kubectl apply -f gatekeeper/constraints/privileged.yaml
k8sprivileged.constraints.gatekeeper.sh/disallow-privileged created
va@Lenovo:~/projects/architecture-pro-propdevelopment/Task7$ kubectl get constrainttemplates
NAME            AGE
k8sprivileged   16s
va@Lenovo:~/projects/architecture-pro-propdevelopment/Task7$ kubectl get constraints
NAME                  ENFORCEMENT-ACTION   TOTAL-VIOLATIONS
disallow-privileged   deny                 0
va@Lenovo:~/projects/architecture-pro-propdevelopment/Task7$

---

kubectl apply -f gatekeeper/constraints/hostpath.yaml
k8shostpath.constraints.gatekeeper.sh/disallow-hostpath created
va@Lenovo:~/projects/architecture-pro-propdevelopment/Task7$ kubectl get constrainttemplates
NAME            AGE
k8shostpath     15s
k8sprivileged   2m14s
va@Lenovo:~/projects/architecture-pro-propdevelopment/Task7$ kubectl get constraints
NAME                                                      ENFORCEMENT-ACTION   TOTAL-VIOLATIONS
k8shostpath.constraints.gatekeeper.sh/disallow-hostpath   deny

NAME                                                          ENFORCEMENT-ACTION   TOTAL-VIOLATIONS
k8sprivileged.constraints.gatekeeper.sh/disallow-privileged   deny                 0
va@Lenovo:~/projects/architecture-pro-propdevelopment/Task7$

---

kubectl apply -f gatekeeper/constraint-templates/runasnonroot.yaml
constrainttemplate.templates.gatekeeper.sh/k8srunasnonroot created
va@Lenovo:~/projects/architecture-pro-propdevelopment/Task7$ kubectl apply -f gatekeeper/constraints/runasnonroot.yaml
k8srunasnonroot.constraints.gatekeeper.sh/enforce-runasnonroot created
va@Lenovo:~/projects/architecture-pro-propdevelopment/Task7$ kubectl get constrainttemplates
NAME              AGE
k8shostpath       2m29s
k8sprivileged     4m28s
k8srunasnonroot   12s
va@Lenovo:~/projects/architecture-pro-propdevelopment/Task7$ kubectl get constraints
NAME                                                      ENFORCEMENT-ACTION   TOTAL-VIOLATIONS
k8shostpath.constraints.gatekeeper.sh/disallow-hostpath   deny                 0

NAME                                                          ENFORCEMENT-ACTION   TOTAL-VIOLATIONS
k8sprivileged.constraints.gatekeeper.sh/disallow-privileged   deny                 0

NAME                                                             ENFORCEMENT-ACTION   TOTAL-VIOLATIONS
k8srunasnonroot.constraints.gatekeeper.sh/enforce-runasnonroot   deny
va@Lenovo:~/projects/architecture-pro-propdevelopment/Task7$

---

kubectl apply -f insecure-manifests/ --namespace=audit-zone
Error from server (Forbidden): error when creating "insecure-manifests/01-privileged-pod.yaml": pods "privileged-pod" is forbidden: violates PodSecurity "restricted:latest": privileged (container "nginx" must not set securityContext.privileged=true), allowPrivilegeEscalation != false (container "nginx" must set securityContext.allowPrivilegeEscalation=false), unrestricted capabilities (container "nginx" must set securityContext.capabilities.drop=["ALL"]), runAsNonRoot != true (pod or container "nginx" must set securityContext.runAsNonRoot=true), seccompProfile (pod or container "nginx" must set securityContext.seccompProfile.type to "RuntimeDefault" or "Localhost")
Error from server (Forbidden): error when creating "insecure-manifests/02-hostpath-pod.yaml": pods "hostpath-pod" is forbidden: violates PodSecurity "restricted:latest": allowPrivilegeEscalation != false (container "nginx" must set securityContext.allowPrivilegeEscalation=false), unrestricted capabilities (container "nginx" must set securityContext.capabilities.drop=["ALL"]), restricted volume types (volume "host-vol" uses restricted volume type "hostPath"), runAsNonRoot != true (pod or container "nginx" must set securityContext.runAsNonRoot=true), seccompProfile (pod or container "nginx" must set securityContext.seccompProfile.type to "RuntimeDefault" or "Localhost")
Error from server (Forbidden): error when creating "insecure-manifests/03-root-user-pod.yaml": pods "root-user-pod" is forbidden: violates PodSecurity "restricted:latest": allowPrivilegeEscalation != false (container "nginx" must set securityContext.allowPrivilegeEscalation=false), unrestricted capabilities (container "nginx" must set securityContext.capabilities.drop=["ALL"]), runAsNonRoot != true (pod or container "nginx" must set securityContext.runAsNonRoot=true), runAsUser=0 (container "nginx" must not set runAsUser=0), seccompProfile (pod or container "nginx" must set securityContext.seccompProfile.type to "RuntimeDefault" or "Localhost")

kubectl apply -f secure-manifests/ --namespace=audit-zone
kubectl get pods -n audit-zone
pod/secure-privileged-pod configured
pod/secure-hostpath-pod configured
pod/secure-root-user-pod configured
NAME                    READY   STATUS    RESTARTS   AGE
secure-hostpath-pod     1/1     Running   0          13m
secure-privileged-pod   1/1     Running   0          13m
secure-root-user-pod    1/1     Running   0          13m

---