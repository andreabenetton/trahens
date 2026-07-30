.PHONY: test crypto-vectors experiments sweep policy-compare unlinkability-compare lifecycle-compare paper check reproduce clean

test:
	PYTHONPATH=simulator python -m unittest discover -s simulator/tests -v

crypto-vectors:
	PYTHONPATH=simulator python tools/generate_crypto_vectors.py --output spec/crypto-test-vectors-c1.json

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

paper:
	mkdir -p build/paper
	latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=build/paper paper/rewrite/main.tex

check:
	./tools/check_repo.sh
	$(MAKE) paper

reproduce:
	$(MAKE) crypto-vectors
	$(MAKE) experiments
	$(MAKE) sweep
	$(MAKE) policy-compare
	$(MAKE) unlinkability-compare
	$(MAKE) lifecycle-compare
	$(MAKE) paper

clean:
	rm -rf build dist
	find simulator -type d -name __pycache__ -prune -exec rm -rf {} +
