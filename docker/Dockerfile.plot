# Image used only to render the figures.
#
# Containerising this keeps Python out of the prerequisites for a reproduction. The versions are
# pinned in eval/plot/requirements.txt, the combination the paper figures were produced with.
FROM python@sha256:6b3223eb4d93718828223966ad316909c39813dee3ee9395204940500792b740

# Force a non-interactive backend: there is no display in the container.
ENV MPLBACKEND=Agg \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /plot

COPY eval/plot/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY eval/plot/*.py ./

ENTRYPOINT ["python"]
