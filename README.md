# AndroidKeyStore

This is the tool library of Android KeyStore, you can use the function of KeyStore quickly and conveniently.

# Download

build.gradle of project

```groovy
buildscript {
    repositories {
        google()
        jcenter()
        maven {
            url = uri("https://maven.pkg.github.com/Chenziquan/AndroidKeyStore")
            credentials {
                username = "Chenziquan"
                password = "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"
            }
        }
    }
}

allprojects {
    repositories {
        google()
        jcenter()
        maven {
            url = uri("https://maven.pkg.github.com/Chenziquan/AndroidKeyStore")
            credentials {
                username = "Chenziquan"
                password = "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"
            }
        }
    }
}
```

build.gradle of module.

```groovy
implementation 'com.pax.jc:androidkeystore:1.0.0'
```