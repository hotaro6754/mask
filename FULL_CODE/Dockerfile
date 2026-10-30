FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir uv==0.8.22
WORKDIR /app
COPY pyproject.toml uv.lock ./
COPY docs/PYPI.md ./docs/PYPI.md
COPY src ./src
RUN uv sync --frozen --no-dev
COPY policies ./policies
COPY bench ./bench
COPY postman ./postman
ENV PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1
EXPOSE 8000 8501
CMD ["maskguard", "serve", "--host", "0.0.0.0", "--port", "8000"]
