FROM maven:3.9.16-eclipse-temurin-25 AS build
WORKDIR /workspace
COPY pom.xml pom.xml
COPY services/customer-service/pom.xml services/customer-service/pom.xml
COPY services/account-service/pom.xml services/account-service/pom.xml
COPY services/transaction-service/pom.xml services/transaction-service/pom.xml
COPY services services
RUN mvn --batch-mode --no-transfer-progress -DskipTests package

FROM eclipse-temurin:25-jre-alpine
WORKDIR /app
ARG APP_MODULE
COPY --from=build /workspace/services/${APP_MODULE}/target/${APP_MODULE}-*.jar app.jar
USER 10001
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-jar", "/app/app.jar"]
