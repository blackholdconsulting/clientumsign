# ---------- Build ----------
FROM maven:3.9.9-eclipse-temurin-21 AS build
WORKDIR /app

# Descargar dependencias primero (cachea mejor)
COPY pom.xml .
RUN mvn -q -U -DskipTests dependency:go-offline

# Copiar el código y compilar
COPY src ./src
RUN mvn -q -U -DskipTests package

# ---------- Runtime ----------
FROM eclipse-temurin:21-jre
WORKDIR /app

# Copia el jar empaquetado por Spring Boot
COPY --from=build /app/target/signer-0.0.1.jar /app/app.jar

# Render usa la variable PORT; Spring Boot la leerá desde application.properties
ENV JAVA_OPTS=""

EXPOSE 8080
CMD ["sh", "-c", "java $JAVA_OPTS -jar /app/app.jar"]
