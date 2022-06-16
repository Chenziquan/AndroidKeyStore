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
implementation 'com.jc:androidkeystore:1.0.0'
```