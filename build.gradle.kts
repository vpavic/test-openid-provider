import org.springframework.boot.gradle.plugin.SpringBootPlugin

plugins {
    java
    id("com.diffplug.gradle.spotless") version "3.23.0"
    id("com.github.ben-manes.versions") version "0.21.0"
    id("org.springframework.boot") version "2.1.5.RELEASE"
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(platform(SpringBootPlugin.BOM_COORDINATES))

    implementation("org.springframework.boot:spring-boot-starter-web")

    implementation("com.github.ben-manes.caffeine:caffeine")
    implementation("com.nimbusds:nimbus-jose-jwt:7.2.1")
    implementation("com.nimbusds:oauth2-oidc-sdk:6.13")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
}

spotless {
    val licenseHeaderFile = rootProject.file("config/spotless/license.java")
    val importOrderFile = rootProject.file("config/eclipse/test-op.importorder")
    val eclipseConfigFile = rootProject.file("config/eclipse/test-op-formatter.xml")

    java {
        trimTrailingWhitespace()
        endWithNewline()
        indentWithSpaces()
        licenseHeaderFile(licenseHeaderFile)
        importOrderFile(importOrderFile)
        removeUnusedImports()
        eclipse().configFile(eclipseConfigFile)
    }
}
