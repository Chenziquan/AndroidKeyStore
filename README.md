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
            url 'https://openrepo.paxengine.com.cn/api/v4/projects/19/packages/maven'
            name "GitLab"
            credentials(HttpHeaderCredentials) {
                name = 'Deploy-Token'
                value = 'tKxMYSwBrxYcDZyVzZAm'
            }
            authentication {
                header(HttpHeaderAuthentication)
            }

        }
    }
}

allprojects {
    repositories {
        google()
        jcenter()
        maven {
            url 'https://openrepo.paxengine.com.cn/api/v4/projects/19/packages/maven'
            name "GitLab"
            credentials(HttpHeaderCredentials) {
                name = 'Deploy-Token'
                value = 'tKxMYSwBrxYcDZyVzZAm'
            }
            authentication {
                header(HttpHeaderAuthentication)
            }

        }
    }
}
```

build.gradle of module.

```groovy
implementation 'com.pax.jc:androidkeystore:1.0.0'
```