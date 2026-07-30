.PHONY: test experiments sweep policy-compare unlinkability-compare paper check reproduce clean

test:
	PYTHONPATH=simulator python -m unittest discover -s simulator/tests -v

experiments:
	./tools/run_experiments.sh

sweep:
	./tools/run_sweep.sh

policy-compare:
	./tools/run_policy_comparison.sh

unlinkability-compare:
	./tools/run_unlinkability_comparison.sh

paper:
	mkdir -p build/paper
	latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=build/paper paper/rewrite/main.tex

check:
	./tools/check_repo.sh
	$(MAKE) paper

reproduce:
	$(MAKE) experiments
	$(MAKE) sweep
	$(MAKE) policy-compare
	$(MAKE) unlinkability-compare
	$(MAKE) paper

clean:
	rm -rf build dist
	find simulator -type d -name __pycache__ -prune -exec rm -rf {} +
