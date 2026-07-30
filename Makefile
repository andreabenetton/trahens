.PHONY: test crypto-vectors c2-symbolic-vectors experiments sweep policy-compare unlinkability-compare lifecycle-compare tagging-compare fragmentation-compare c2-compare paper check reproduce clean

test:
	PYTHONPATH=simulator python -m unittest discover -s simulator/tests -v

crypto-vectors:
	PYTHONPATH=simulator python tools/generate_crypto_vectors.py --output spec/crypto-test-vectors-c1.json

c2-symbolic-vectors:
	PYTHONPATH=simulator python tools/generate_c2_symbolic_vectors.py --output spec/crypto-test-vectors-c2-symbolic.json

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
	$(MAKE) c2-symbolic-vectors
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
