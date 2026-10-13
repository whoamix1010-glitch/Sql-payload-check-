package scanner

import "crypto/tls"

// similarity returns a 0..1 ratio of how alike two response bodies are, using a
// lightweight bigram (Sørensen–Dice) comparison. It is cheap and good enough to
// tell "page looks the same" from "page changed" for boolean-based detection.
func similarity(a, b string) float64 {
	if a == b {
		return 1.0
	}
	if len(a) < 2 || len(b) < 2 {
		return 0.0
	}
	ba := bigrams(a)
	bb := bigrams(b)
	if len(ba) == 0 || len(bb) == 0 {
		return 0.0
	}
	matches := 0
	for g, n := range ba {
		if m, ok := bb[g]; ok {
			matches += min(n, m)
		}
	}
	return (2.0 * float64(matches)) / float64(countAll(ba)+countAll(bb))
}

func bigrams(s string) map[string]int {
	m := make(map[string]int)
	for i := 0; i+1 < len(s); i++ {
		m[s[i:i+2]]++
	}
	return m
}

func countAll(m map[string]int) int {
	total := 0
	for _, n := range m {
		total += n
	}
	return total
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func insecureTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} // opt-in via --insecure, for self-signed lab targets
}
