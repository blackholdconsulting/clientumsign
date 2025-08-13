# ---------- Build ----------
FROM maven:3.9.9-eclipse-temurin-21 AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn -q -DskipTests package

# ---------- Runtime ----------
FROM eclipse-temurin:21-jre
WORKDIR /app
ENV JAVA_OPTS="-Xms128m -Xmx512m"
ENV PORT=8080
EXPOSE 8080
COPY --from=build /app/target/*.jar /app/app.jar
CMD ["sh", "-c", "java $JAVA_OPTS -jar /app/app.jar"]
