{% macro log_scale(column_name) %}
    LN(1 + COALESCE({{ column_name }}, 0))
{% endmacro %}

{% macro log_scale_sum(column_name, condition=None) %}
    {% if condition %}
        LN(1 + SUM(CASE WHEN {{ condition }} THEN {{ column_name }} ELSE 0 END))
    {% else %}
        LN(1 + SUM({{ column_name }}))
    {% endif %}
{% endmacro %}

{% macro safe_ratio(numerator, denominator) %}
    {{ numerator }} / NULLIF({{ denominator }}, 0)::FLOAT
{% endmacro %}
