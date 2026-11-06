package com.zhouzhou.agent.rag;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;

import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.ai.vectorstore.filter.Filter;
import org.springframework.stereotype.Component;

/**
 * 没有向量库时让应用能启动的文档存储。它按元数据过滤，不做语义相似度。
 * 文章里的隔离断言走的是 EnterpriseRagService 交给 VectorStore 的过滤表达式。
 */
@Component
public class InMemoryDocumentStore implements VectorStore {

    private final List<Document> documents = new CopyOnWriteArrayList<>();

    @Override
    public void add(List<Document> documents) {
        this.documents.addAll(documents);
    }

    @Override
    public void delete(List<String> idList) {
        this.documents.removeIf(document -> idList.contains(document.getId()));
    }

    @Override
    public void delete(Filter.Expression filterExpression) {
        this.documents.removeIf(document -> matches(document, filterExpression));
    }

    @Override
    public List<Document> similaritySearch(SearchRequest request) {
        List<Document> matched = new ArrayList<>();
        for (Document document : this.documents) {
            if (matches(document, request.getFilterExpression())) {
                matched.add(document);
                if (matched.size() >= request.getTopK()) {
                    break;
                }
            }
        }
        return List.copyOf(matched);
    }

    private static boolean matches(Document document, Filter.Expression expression) {
        if (expression == null) {
            return true;
        }
        return switch (expression.type()) {
            case AND -> matches(document, (Filter.Expression) expression.left())
                    && matches(document, (Filter.Expression) expression.right());
            case EQ -> Objects.equals(metadata(document, expression), literal(expression));
            case LTE -> compare(document, expression) <= 0;
            default -> false;
        };
    }

    private static Object metadata(Document document, Filter.Expression expression) {
        if (!(expression.left() instanceof Filter.Key key)) {
            return null;
        }
        return document.getMetadata().get(key.key());
    }

    private static Object literal(Filter.Expression expression) {
        if (!(expression.right() instanceof Filter.Value value)) {
            return null;
        }
        return value.value();
    }

    private static int compare(Document document, Filter.Expression expression) {
        Object left = metadata(document, expression);
        Object right = literal(expression);
        if (left instanceof Number leftNumber && right instanceof Number rightNumber) {
            return Double.compare(leftNumber.doubleValue(), rightNumber.doubleValue());
        }
        return 1;
    }
}
