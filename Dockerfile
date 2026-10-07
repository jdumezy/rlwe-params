FROM sagemath/sagemath:10.9@sha256:e068670ae5863b54b2550e72437ec637b0283acb0dc712c8584c124dbf44e667

USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir /work && chown sage:sage /work

USER sage
WORKDIR /home/sage/ckks-estimator
COPY --chown=sage:sage pyproject.toml ./
COPY --chown=sage:sage ckks_estimator ./ckks_estimator
ENV CKKS_ESTIMATOR_BACKENDS=/home/sage/backends
RUN sage -python -m pip install --no-deps --no-build-isolation . \
    && sage -python -m ckks_estimator setup \
    && sage -python -c "from ckks_estimator.estimators import MalbEstimator, TabOgEstimator; MalbEstimator(); TabOgEstimator()"

WORKDIR /work
ENTRYPOINT ["sage", "-python", "-m", "ckks_estimator"]
CMD ["--help"]
