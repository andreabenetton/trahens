.PHONY: test experiments paper check clean

test:
	PYTHONPATH=simulator python -m unittest discover -s simulator/tests -v

experiments:
	./tools/run_experiments.sh

paper:
	mkdir -p build/paper
	latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=build/paper paper/rewrite/main.tex

check:
	./tools/check_repo.sh
	$(MAKE) paper

clean:
	rm -rf build dist reports/*.json
