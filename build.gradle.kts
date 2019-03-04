import org.springframework.boot.gradle.plugin.SpringBootPlugin

plugins {
    java
    id("com.diffplug.gradle.spotless") version "3.18.0"
    id("com.github.ben-manes.versions") version "0.20.0"
    id("org.springframework.boot") version "2.1.3.RELEASE"
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(platform(SpringBootPlugin.BOM_COORDINATES))

    implementation("org.springframework.boot:spring-boot-starter-web")

    implementation("com.github.ben-manes.caffeine:caffeine")
    implementation("com.nimbusds:nimbus-jose-jwt:7.0")
    implementation("com.nimbusds:oauth2-oidc-sdk:6.5")

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
