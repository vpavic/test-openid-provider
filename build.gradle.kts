plugins {
    java
    checkstyle
    id("com.github.ben-manes.versions") version "0.20.0"
    id("org.springframework.boot") version "2.1.1.RELEASE"
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(platform("org.springframework.boot:spring-boot-dependencies:2.1.1.RELEASE"))

    implementation("org.springframework.boot:spring-boot-starter-web")

    implementation("com.github.ben-manes.caffeine:caffeine")
    implementation("com.nimbusds:nimbus-jose-jwt:6.5.1")
    implementation("com.nimbusds:oauth2-oidc-sdk:6.5")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
}

checkstyle {
    toolVersion = "8.15"
}
