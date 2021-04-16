import org.springframework.boot.gradle.plugin.SpringBootPlugin

plugins {
    java
    id("com.diffplug.spotless").version("5.12.1")
    id("com.github.ben-manes.versions").version("0.38.0")
    id("org.springframework.boot").version("2.4.5")
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(platform(SpringBootPlugin.BOM_COORDINATES))
    implementation("com.github.ben-manes.caffeine:caffeine")
    implementation("com.nimbusds:oauth2-oidc-sdk")
    implementation("org.springframework.boot:spring-boot-starter-web")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
}

tasks.withType<Test> {
    useJUnitPlatform()
}

spotless {
    java {
        trimTrailingWhitespace()
        endWithNewline()
        indentWithSpaces()
        licenseHeaderFile(rootProject.file("config/spotless/license.java"))
        importOrderFile(rootProject.file("config/eclipse/test-op.importorder"))
        removeUnusedImports()
        eclipse().configFile(rootProject.file("config/eclipse/test-op-formatter.xml"))
    }
}
