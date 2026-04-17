package risk

import "testing"

func TestEvaluateCommandBlocksConfirmedBypasses(t *testing.T) {
	engine := NewEngine(nil, []string{"/home/sauron/.ssh", "/home/sauron/.kube", "/etc", "/var"}, true)

	tests := []string{
		"kubectl delete pods -n authsec-prod -l app=prod-authsec",
		"k delete pods -n authsec-prod -l app=prod-authsec",
		"/usr/bin/kubectl delete pods -n authsec-prod",
		"/usr/bin/.kubectl.shield-real delete pods -n authsec-prod",
		"kubectl --context prod delete pods -n authsec-prod",
		"env kubectl delete pods -n authsec-prod",
		"bash -c kubectl delete pods -n authsec-prod",
		"git -C /tmp/repo push --force origin main",
		"docker --context prod system prune --force",
		"curl -X DELETE https://kubernetes.default/api/v1/namespaces/authsec-prod/pods/prod-authsec",
		"python -c delete_namespaced_pod",
	}

	for _, command := range tests {
		t.Run(command, func(t *testing.T) {
			eval := engine.EvaluateCommand(command)
			if eval.Score <= 30 {
				t.Fatalf("expected score above threshold, got %d (%v)", eval.Score, eval.Reasons)
			}
		})
	}
}

func TestEvaluateCommandAllowsReadOnlyCommands(t *testing.T) {
	engine := NewEngine(nil, nil, true)

	tests := []string{
		"kubectl get pods -n authsec-prod",
		"git status",
		"docker ps",
		"ls -la",
	}

	for _, command := range tests {
		t.Run(command, func(t *testing.T) {
			eval := engine.EvaluateCommand(command)
			if eval.Score > 30 {
				t.Fatalf("expected score at or below threshold, got %d (%v)", eval.Score, eval.Reasons)
			}
		})
	}
}
