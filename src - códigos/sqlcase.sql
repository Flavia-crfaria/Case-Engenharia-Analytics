Consultas SQL utilizadas no Athena


-- CASE CYBER SECURITY ANALYTICS
-- Consultas utilizadas para ingestão, exploração e qualidade
-- Banco de dados: workspace_db

1. Criação da tabela RAW de ativos
 CREATE EXTERNAL TABLE workspace_db.tb_ativos_raw (
ativo_id STRING,
sistema STRING,
criticidade STRING,
dominio STRING,
ambiente STRING,
localidade STRING,
status_ativo STRING
)
ROW FORMAT DELIMITED
FIELDS TERMINATED BY ';'
STORED AS TEXTFILE
LOCATION 's3://***conta consumer***/FCEKUGG/cyber-analytics-case-flavia/raw/ativos/'
TBLPROPERTIES (
'skip.header.line.count' = '1'
);

Validação da carga
SELECT *
FROM workspace_db.tb_ativos_raw
LIMIT 10;

Contagem de ativos carregados

SELECT COUNT(*) AS total_ativos
FROM workspace_db.tb_ativos_raw;

-----------------------------------------------------------------------------------------------------
2. Criação da tabela RAW de vulnerabilidades

CREATE EXTERNAL TABLE workspace_db.tb_vulnerabilidades_raw (
vuln_id STRING,
ativo_id STRING,
severidade STRING,
origem STRING,
data_abertura STRING,
data_correcao STRING,
status STRING,
cvss_score DOUBLE
)
ROW FORMAT DELIMITED
FIELDS TERMINATED BY ';'
STORED AS TEXTFILE
LOCATION 's3://**conta consumer***/FCEKUGG/cyber-analytics-case-flavia/raw/vulnerabilidades/'
TBLPROPERTIES (
'skip.header.line.count' = '1'
);
Validação da carga

SELECT *
FROM workspace_db.tb_vulnerabilidades_raw
LIMIT 10;

Contagem de vulnerabilidades carregadas
SELECT COUNT(*) AS total_vulnerabilidades
FROM workspace_db.tb_vulnerabilidades_raw;

-----------------------------------------------------------------------------------------------
3. Data Quality Assessment

3.1 Validação da criticidade dos ativos

SELECT
criticidade,
COUNT(*) AS quantidade
FROM workspace_db.tb_ativos_raw
GROUP BY criticidade
ORDER BY quantidade DESC;

Visualização de espaços antes ou depois dos valores
SELECT
CONCAT('[', criticidade, ']') AS criticidade_formatada,
COUNT(*) AS quantidade
FROM workspace_db.tb_ativos_raw
GROUP BY criticidade
ORDER BY quantidade DESC;

Quantidade de criticidades ausentes ou não informadas
SELECT
COUNT(*) AS criticidades_nao_inf*rmadas
FROM workspace_db.tb_ativos*raw
WHERE criticidade IS NULL
O* TRIM(criticidade) = ''
OR LOWE*(TRIM(criticidade)) = 'n/a';

3.2 Validação da severidade das vulnerabilidades
SELEC*
severidade,
COUNT(*) AS q*antidade
FROM workspace_db.tb_vuln*rabilidades_raw
GROUP BY severidad*
ORDER BY quantidade DESC;


Visualização de espaços antes ou depois dos valores
SELECT
* CONCAT('[', severidade, ']') AS *everidade_formatada,
COUNT(*) *S quantidade
FROM workspace_db.tb_*ulnerabilidades_raw
GROUP BY sever*dade
ORDER BY quantidade DESC;

Quantidade de severidades ausentes ou não informadas
SELECT
COUNT(*) AS severidades_nao_informadas
FROM workspace_db.tb_vulnerabilidades_raw
WHERE severidade IS NULL
OR TRIM(severidade) = ''
OR LOWER(TRIM(severidade)) = 'n/a';

3.3 Validação dos status
SELECT
status,
COUNT(*) AS quantidade
FROM workspace_db.tb_vulnerabilidades_raw
GROUP BY status
ORDER BY quantidade DESC;
Verificação de status nulos ou vazios
SQL
SELECT
COUNT(*) AS status_nao_informados
FROM workspace_db.tb_vulnerabilidades_raw
WHERE status IS NULL
OR TRIM(status) = '';


3.4 Integridade referencial entre vulnerabilidades e ativos
SELECT
v.ativo_id,
COUNT(*) AS quantidade
FROM workspace_db.tb_vulnerabilidades_raw v
LEFT JOIN workspace_db.tb_ativos_raw a
ON v.ativo_id = a.ativo_id
WHERE a.ativo_id IS NULL
GROUP BY v.ativo_id
ORDER BY quantidade DESC;

Detalhamento dos registros associados ao ativo inexistente
SELECT
v.*
FROM workspace_db.tb_vulnerabilidades_raw v
LEFT JOIN workspace_db.tb_ativos_raw a
ON v.ativo_id = a.ativo_id
WHERE a.ativo_id IS NULL;

Quantidade total de vulnerabilidades sem ativo correspondente
SELECT
COUNT(*) AS vulnerabilidades_sem_ativo
FROM workspace_db.tb_vulnerabilidades_raw v
LEFT JOIN workspace_db.tb_ativos_raw a
ON v.ativo_id = a.ativo_id
WHERE a.ativo_id IS NULL;


3.5 Validação inicial das datas de abertura
SELECT
COUNT(*) AS quantidade_datas_nao_convertidas
FROM workspace_db.tb_vulnerabilidades_raw
WHERE TRY_CAST(data_abertura AS DATE) IS NULL;

Visualização dos valores não convertidos
SELECT DISTINCT
data_abertura
FROM workspace_db.tb_vulnerabilidades_raw
WHERE TRY_CAST(data_abertura AS DATE) IS NULL
ORDER BY data_abertura
LIMIT 100;


Visualização de exemplos de datas existentes
SELECT DISTINCT
data_abertura
FROM workspace_db.tb_vulnerabilidades_raw
LIMIT 50;

Observação: como a base original possuía datas em formatos diferentes, a conversão definitiva e a identificação das 78 datas não recuperáveis foram realizadas em Python.

3.6 Validação das datas de correção
SELECT
COUNT(*) AS datas_correcao_nao_convertidas
FROM workspace_db.tb_vulnerabilidades_raw
WHERE data_correcao IS NOT NULL
AND TRIM(data_correcao) <> ''
AND TRY_CAST(data_correcao AS DATE) IS NULL;

Visualizar exemplos de datas de correção não convertidas
SELECT DISTINCT
data_correcao
FROM workspace_db.tb_vulnerabilidades_raw
WHERE data_correcao IS NOT NULL
AND TRIM(data_correcao) <> ''
AND TRY_CAST(data_correcao AS DATE) IS NULL
ORDER BY data_correcao
LIMIT 100;

3.7 Validação da origem das vulnerabilidades
SELECT
origem,
COUNT(*) AS quantidade
FROM workspace_db.*b_vulnerabilidades_raw
GROUP BY or*gem
ORDER BY quantidade DESC;

Visualização de possíveis espaços invisíveis
SELECT
C*NCAT('[', origem, ']') AS origem_f*rmatada,
COUNT(*) AS quantidad*
FROM workspace_db.tb_vulnerabilid*des_raw
GROUP BY origem
ORDER BY q*antidade DESC;

Agrupamento preliminar em letras minúsculas
SELECT
LOWER(TRIM(origem*) AS origem_normalizada,
COUNT**) AS quantidade
FROM workspace_db*tb_vulnerabilidades_raw
GROUP BY L*WER(TRIM(origem))
ORDER BY quantid*de DESC;

3.8 Validação do CVSS Score
SELECT
COUNT(*) A* total_registros,
COUNT(cvss_s*ore) AS registros_com_cvss,
MI*(cvss_score) AS cvss_minimo,
M*X(cvss_score) AS cvss_maximo,
*VG(cvss_score) AS cvss_medio
FROM *orkspace_db.tb_vulnerabilidades_ra*;

Identificação de valores fora do intervalo esperado
SELECT
vuln_id,
ativo_id,* cvss_score
FROM workspace_db.t*_vulnerabilidades_raw
WHERE cvss_s*ore < 0
OR cvss_score > 10;

3.9 Validação de coerência entre status e data de correção
Vulnerabilidades corrigidas sem data de correção
SELECT
* COUNT(*) AS corrigidas_sem_data
F*OM workspace_db.tb_vulnerabilidade*_raw
WHERE status = 'Corrigida'
*ND (
data_correcao IS NULL* OR TRIM(data_correcao));


------------------------------------------------------------------------- 

CREATE EXTERNAL TABLE workspace*db.tb_risco_analitico (
vuln_i* STRING,
ativo_id STRING,
*everidade STRING,
origem STRIN*,
data_abertura STRING,
da*a_correcao STRING,
status STRI*G,
cvss_score STRING,
seve*idade_tratada STRING,
origem_t*atada STRING,
ativo_inexistent* INT,
data_abertura_tratada ST*ING,
data_invalida INT,
si*tema STRING,
criticidade STRIN*,
dominio STRING,
ambiente*STRING,
localidade STRING,
*status_ativo STRING,
criticida*e_tratada STRING,
peso_critici*ade INT,
peso_severidade INT,
* risk_score INT
)
ROW FORMAT DEL*MITED
FIELDS TERMINATED BY ';'
STO*ED AS TEXTFILE
LOCATION 's3://**conta consumer***/FC*KUGG/cyber-analytics-case-flavia/t*usted/risco_analitico/'
TBLPROPERT*ES (
'skip.header.line.count' * '1'
);

Validação da tabela analítica


SELECT *
FROM workspace_db.tb_risco_analitico
LIMIT 10;

Contagem de registros
SELECT
COUNT(*) AS total_registros,
COUNT(DISTINCT vuln_id) AS vulnerabilidades_distintas,
COUNT(DISTINCT ativo_id) AS ativos_distintos
FROM workspace_db.tb_risco_analitico;

6. Consultas de validação da camada Trusted

6.1 Severidade tratada

SELECT
severidade_tratada,
COUNT(*) AS quantidade
FROM workspace_db.tb_risco_analitico
GROUP BY severidade_tratada
ORDER BY quantidade DESC;

6.2 Criticidade tratada

SELECT
criticidade_tratada,
COUNT(*) AS quantidade
FROM workspace_db.tb_risco_analitico
GROUP BY criticidade_tratada
ORDER BY quantidade DESC;

6.3 Origem tratada
SELECT
origem_tratada,
COUNT(*) AS quantidade
FROM workspa*e_db.tb_risco_analitico
GROUP BY o*igem_tratada
ORDER BY quantidade DESC;