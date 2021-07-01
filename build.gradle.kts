import org.springframework.boot.gradle.plugin.SpringBootPlugin

plugins {
	java
	id("com.diffplug.spotless").version("5.12.1")
	id("com.github.ben-manes.versions").version("0.38.0")
	id("org.springframework.boot").version("2.4.5")
}

java {
	toolchain {
		languageVersion.set(JavaLanguageVersion.of(11))
	}
}

repositories {
	mavenCentral()
}

dependencies {
	implementation(platform(SpringBootPlugin.BOM_COORDINATES))
	implementation("com.github.ben-manes.caffeine:caffeine")
	implementation("com.nimbusds:nimbus-jose-jwt") {
		version { strictly("8.22.1") }
	}
	implementation("com.nimbusds:oauth2-oidc-sdk") {
		version { strictly("8.36.2") }
	}
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
		indentWithTabs()
		licenseHeaderFile(rootProject.file("config/spotless/license.java"))
		importOrder("java", "javax", "", "io.github.vpavic", "\\#")
		removeUnusedImports()
	}

	kotlinGradle {
		trimTrailingWhitespace()
		endWithNewline()
		indentWithTabs()
	}
}
