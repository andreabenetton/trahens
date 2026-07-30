.PHONY: test crypto-vectors r1-vectors t1-vectors t2-vectors t3-vectors t4-vectors c2-symbolic-vectors c2-k2-audit c2-k2-exhaustive r1-compare t1-compare t2-compare t3-compare t4-compare experiments sweep policy-compare unlinkability-compare lifecycle-compare tagging-compare fragmentation-compare c2-compare paper check reproduce clean

test:
	PYTHONPATH=simulator python -m unittest discover -s simulator/tests -v

crypto-vectors:
	PYTHONPATH=simulator python tools/generate_crypto_vectors.py --output spec/crypto-test-vectors-c1.json

r1-vectors:
	PYTHONPATH=simulator python tools/generate_r1_vectors.py --output spec/r1-test-vectors.json

t1-vectors:
	PYTHONPATH=simulator python tools/generate_t1_vectors.py --output spec/t1-test-vectors.json

t2-vectors:
	PYTHONPATH=simulator python tools/generate_t2_vectors.py --output spec/t2-test-vectors.json

t4-vectors:
	PYTHONPATH=simulator python tools/generate_t4_vectors.py --output spec/t4-test-vectors.json

t3-vectors:
	PYTHONPATH=simulator python tools/generate_t3_vectors.py --output spec/t3-test-vectors.json

c2-symbolic-vectors:
	PYTHONPATH=simulator python tools/generate_c2_symbolic_vectors.py --output spec/crypto-test-vectors-c2-symbolic.json

c2-k2-audit:
	PYTHONPATH=simulator python tools/generate_c2_k2_audit.py --output reports/c2-k2-transcription-audit.json

c2-k2-exhaustive:
	PYTHONPATH=simulator python tools/c2_k2_exhaustive_check.py --output reports/c2-k2-small-chain-exhaustive.json

r1-compare:
	./tools/run_r1_comparison.sh

t1-compare:
	./tools/run_t1_comparison.sh

t2-compare:
	./tools/run_t2_comparison.sh

t3-compare:
	./tools/run_t3_comparison.sh

t4-compare:
	./tools/run_t4_comparison.sh

experiments:
	./tools/run_experiments.sh

sweep:
	./tools/run_sweep.sh

policy-compare:
	./tools/run_policy_comparison.sh

unlinkability-compare:
	./tools/run_unlinkability_comparison.sh

lifecycle-compare:
	./tools/run_lifecycle_comparison.sh

tagging-compare:
	./tools/run_tagging_comparison.sh

fragmentation-compare:
	./tools/run_fragmentation_comparison.sh

c2-compare:
	./tools/run_c2_comparison.sh

paper:
	mkdir -p build/paper
	latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=build/paper paper/rewrite/main.tex

check:
	./tools/check_repo.sh
	$(MAKE) paper

reproduce:
	$(MAKE) crypto-vectors
	$(MAKE) r1-vectors
	$(MAKE) t1-vectors
	$(MAKE) t2-vectors
	$(MAKE) t3-vectors
	$(MAKE) t4-vectors
	$(MAKE) c2-symbolic-vectors
	$(MAKE) c2-k2-audit
	$(MAKE) c2-k2-exhaustive
	$(MAKE) r1-compare
	$(MAKE) t1-compare
	$(MAKE) t2-compare
	$(MAKE) t3-compare
	$(MAKE) t4-compare
	$(MAKE) experiments
	$(MAKE) sweep
	$(MAKE) policy-compare
	$(MAKE) unlinkability-compare
	$(MAKE) lifecycle-compare
	$(MAKE) tagging-compare
	$(MAKE) fragmentation-compare
	$(MAKE) c2-compare
	$(MAKE) paper

clean:
	rm -rf build dist
	find simulator -type d -name __pycache__ -prune -exec rm -rf {} +
