Parse.Cloud.define('hello', function(req, res) {
    res.success('Hi');
    console.log('bloom-parse-server cloud-code: hello function');
});

Parse.Cloud.define('testDB', function(req, res) {
    console.log('bloom-parse-server cloud-code: testDB');
    try{
        console.log('bloom-parse-server cloud-code: testDB: trying to read GameScore');
        var GameScore = Parse.Object.extend("GameScore");
        var query = new Parse.Query(GameScore);
        query.count({
            success: function(gameScore) {
                console.log('bloom-parse-server cloud-code: testDB: GameScore read succeeded');
            },
            error: function(object, error) {
                console.log('bloom-parse-server cloud-code: testDB: GameScore read failed: '+error);
            }
        });
    } catch(ex) {
        console.log('bloom-parse-server cloud-code: testDB: testDB GameScore read threw exception: '+ex);
    }

    try {
        var parseClass = Parse.Object.extend("testDB");
        var instance = new parseClass();
        instance.set("test", "foo");
        console.log('bloom-parse-server cloud-code: testDB: writing...');
        instance.save(null, { useMasterKey: true,
            success: function (newObj) {
                 console.log('bloom-parse-server cloud-code: testDB: save succeeded');
            },
            error: function (error) {
                console.log('bloom-parse-server cloud-code: testDB: save failed'+error);
            }
        });

    } catch(error) {
        console.log('bloom-parse-server cloud-code: testDB: testDB failed: '+error);
        res.error("write failed: "+error);
    }
    res.success('This function is not sophisticated enough to wait for async calls. Check server log to verify it completed.');
});

// This job updates all current records 'search' field.
// Enhance: pull out common code in this and beforeSave("book").
Parse.Cloud.define("populateSearch", function(request, response) {
    // Set up to modify user data
    // Parse.Cloud.useMasterKey();
    console.log('entering parse-server-example main.js define populateSearch');
    var counter = 0;
    // Query for all books
    var query = new Parse.Query('books');
    query.each(function(book) {
        var tags = book.get("tags");
        var search = book.get("title").toLowerCase();
        var index;
        if (tags) {
            console.log('TAGS IS DEFINED IN populateSearch');
            for (index = 0; index < tags.length; ++index) {
                search = search + " " + tags[index].toLowerCase();
            }
        } else {
            book.set("tags", []); //repair broken database element so we can save it. Tags should not be null for mongoDB
        }
        book.set("search", search);
        counter += 1;
        return book.save(null, { useMasterKey: true }).then(
            function() {},
            function(error) {
                console.log("book.save failed: " + error);
                response.error("book.save failed: " + error);
            });
    }).then(function() {
        // Set the job's success status
        response.success("Update completed successfully.");
    }, function(error) {
        // Set the job's error status
        response.error("Uh oh, something went wrong in populateSearch: " + error);
    });
});

// This job will remove any language records which currently do not have any books which use them.
// The purpose is to keep BloomLibrary.org from displaying languages with no books.
// It is scheduled to run every day. (parse.com -> Core -> Jobs)
// It can be run manually using the following from the command line:
// curl -X POST -H "X-Parse-Application-Id: <insert app ID>"  -H "X-Parse-Master-Key: <insert master key>" -d '{}' https://api.parse.com/1/jobs/removeUnusedLanguages
// (In theory, the -d '{}' shouldn't be needed because we are not passing any parameters, but it doesn't work without it.)
Parse.Cloud.define("removeUnusedLanguages", function(request, response) {
    // Set up to modify data
    //Parse.Cloud.useMasterKey();
    console.log('entering parse-server-example main.js define removeUnusedLanguages');

    var allLangQuery = new Parse.Query('language');
    allLangQuery.find().then(function (languages) {
        var promise = Parse.Promise.as();
        for (var i = 0; i < languages.length; i++) {

            // Use IIFE to pass the correct language down
            (function() {
                var lang = languages[i];
                var bookQuery = new Parse.Query('books');
                bookQuery.equalTo('langPointers', lang);
                promise = promise.then(function () {
                    return bookQuery.count().then(function (count) {
                        if (count === 0) {
                            console.log("Deleting language " + lang.get('name') + " because no books use it.");
                            return lang.destroy();
                        }
                    });
                });
            }());
        }
        return promise;
    }).then(function () {
        response.success("removeUnusedLanguages completed successfully.");
    }, function (error) {
        response.error("Error in removeUnusedLanguages: " + error);
    });
});

//A background job to populate usageCounts for languages and tags
//To schedule this job on parse.com, go to Core > Jobs > Schedule a Job
//In that menu, 1) enter an arbitrary description, 2) select the job name "populateCounts",
//and 3) set repeat to either every day at some time or every so many minutes/hours.
//Click "Schedule Job." The job will henceforth be run at the specified interval.
//To run the job a single time, either click "Run Now" on the scheduled populateCounts job on the parse.com Jobs menu,
//or run this command from the command line:
//curl -X POST -H "X-Parse-Application-Id: <insert ID>"  -H "X-Parse-Master-Key: <insert Master key>" -d "{}" https://api.parse.com/1/jobs/populateCounts
Parse.Cloud.define("populateCounts", function(request, response) {
    //Parse.Cloud.useMasterKey();
    console.log('entering parse-server-example main.js define populateCounts');

    var counters = { language: {}, tag: {}};

    //Query each tag
    var tagQuery = new Parse.Query('tag');
    tagQuery.each(function(tag) {
        //Initial tag counters are 0
        counters.tag[tag.get('name')] = 0;
    }).then(function() {
        //Create a book query
        var bookQuery = new Parse.Query('books');
        bookQuery.limit(1000); // default 100; unfortunately cannot set higher than 1000; need to do repeat queries to handle.

        //Analyze a book's tags and languages and increment proper counts
        function incrementBookUsageCounts(books, index) {
            //If we finished all the books, return resolved promise
            if(index >= books.length) {
                return Parse.Promise.as();
            }

            var book = books[index];

            //Increment book's languages' counts
            //Since we shouldn't worry about invalid languages,
            //this process needs no requests to the server and may be iterative
            var langPtrs = book.get("langPointers");
            if (langPtrs){
                for (var i = 0; i < langPtrs.length; i++) {
                    var onePtr = langPtrs[i];
                    var id = onePtr.id;
                    if (!(id in counters.language)) {
                        counters.language[id] = 0;
                    }
                    counters.language[id]++;
                }
            }

            var tags = book.get('tags');
            if(tags) {
                //Recursively increment book's tags' counts
                return incrementTagUsageCount(tags, 0).then(function() {
                    //Next book
                    return incrementBookUsageCounts(books, index + 1);
                });
            }

            //Next book (when no tags)
            return incrementBookUsageCounts(books, index + 1);
        }

        //Increment a given tag's count
        function incrementTagUsageCount(tags, index) {
            if(index >= tags.length) { //Base case
                //Resolved promise
                return Parse.Promise.as();
            }
            else if(tags[index] in counters.tag) {
                counters.tag[tags[index]]++;
                //Next tag
                return incrementTagUsageCount(tags, index + 1);
            }
            else {
                //If tag is not one already in the database, add the tag to the database
                counters.tag[tags[index]] = 1;
                var parseClass = Parse.Object.extend('tag');
                var newTag = new parseClass();
                newTag.set("name", tags[index]);
                return newTag.save(null, { useMasterKey: true }).then(
                    function() {
                        console.log("created tag " + tags[index]);
                        //Next tag
                        return incrementTagUsageCount(tags, index + 1);
                    },
                    function(error) {
                        console.log("newTag.save failed: " + error);
                        response.error("newTag.save failed: " + error);
                    }
                );
            }
        }

        //Make query, then initialize recursive book analysis; return promise for next then in promise chain
        return bookQuery.find().then(function (results) {
            return incrementBookUsageCounts(results, 0);
        });
    }).then(function () {
        function setLangUsageCount(data, index) {
            //When done, return resolved promise
            if(index >= data.length) {
                return Parse.Promise.as();
            }

            var item = data[index];
            item.set("usageCount", counters.language[item.id] || 0);
            return item.save(null, { useMasterKey: true }).then(
                function () {
                    //Next language
                    return setLangUsageCount(data, index + 1);
                },
                function(error) {
                    console.log("item.save failed: " + error);
                    response.error("item.save failed: " + error);
                }
            );
        }

        var langQuery = new Parse.Query('language');

        //Cycle through languages, assigning usage counts
        return langQuery.find().then(function (results) {
            //Start recursion
            return setLangUsageCount(results, 0);
        });
    }).then(function() {
        function setTagUsageCount(data, index) {
            //Return resolved promise when done
            if(index >= data.length) {
                return Parse.Promise.as();
            }

            var item = data[index];
            var count = counters.tag[item.get('name')];
            if(count > 0) {
                item.set("usageCount", count);
                return item.save(null, { useMasterKey: true }).then(function () {
                    return setTagUsageCount(data, index + 1);
                }
                ,
                function(error) { console.log("item.save failed: " + error); response.error("item.save failed: " + error); });
            }
            else {
                //Destroy tag with count of 0
                return item.destroy().then(function() {
                    return setTagUsageCount(data, index + 1);
                });
            }
        }

        var tagQuery2 = new Parse.Query('tag');

        //Cycle through tags in database
        return tagQuery2.find().then(function(results) {
            //Begin recursion
            return setTagUsageCount(results, 0);
        });
    }).then(function() {
        response.success("Tag and Language usage counts updated!");
    }, function(error) {
        response.error("populateCounts terminated unsuccessfully with error: " + error);
    });
});

// Makes new and updated books have the right search string and ACL.
Parse.Cloud.beforeSave("books", function(request, response) {
    var book = request.object;

    console.log('entering parse-server-example main.js beforeSave books');

    // If updateSource is not set, the new/updated record came from the desktop application
    var updateSource = request.object.get("updateSource");
    if (!updateSource) {
        book.addUnique("tags", "system:Incoming");
    } else {
        request.object.unset("updateSource");
    }

    var tags = book.get("tags");
    var search = book.get("title").toLowerCase();
    var index;
    if (tags) {
        for (index = 0; index < tags.length; ++index) {
            search = search + " " + tags[index].toLowerCase();
        }
    }
    request.object.set("search", search);

    var creator = request.user;

    if (creator && request.object.isNew()) { // created normally, someone is logged in and we know who, restrict access
        var newACL = new Parse.ACL();
        // According to https://parse.com/questions/beforesave-user-set-permissions-for-self-and-administrators,
        // a user can always write their own object, so we don't need to permit that.
        newACL.setPublicReadAccess(true);
        newACL.setRoleWriteAccess("moderator", true); // allows moderators to delete
        newACL.setWriteAccess(creator, true);
        request.object.setACL(newACL);
    }
    response.success();
});

Parse.Cloud.afterSave("books", function(request) {
    const bookshelfPrefix = "bookshelf:";
    var book = request.object;
    book.get("tags").filter(function(element) {
        return element.indexOf(bookshelfPrefix) > -1;
    }).map(function(element) {
        return element.substr(bookshelfPrefix.length);
    }).forEach(function(key) {
        var Bookshelf = Parse.Object.extend("bookshelf");
        var query = new Parse.Query(Bookshelf);
        query.equalTo("key", key);
        query.count({
            success: function(count) {
                if(count == 0) {
                    //Create a new bookshelf to contain this book with default properties
                    var bookshelf = new Bookshelf();
                    bookshelf.set("key", key);
                    bookshelf.set("englishName", key);
                    bookshelf.set("normallyVisible", false);
                    bookshelf.save(null, { useMasterKey: true }).then(
                        function() {},
                        function(error) {
                            console.log("bookshelf.save failed: " + error);
                            response.error("bookshelf.save failed: " + error);
                        }
                    );
                }
            },
            error: function(error) {
                console.log("get error: " + error);
            }
        })
    });
})

Parse.Cloud.afterSave("downloadHistory", function(request) {
    //Parse.Cloud.useMasterKey();
    console.log('entering parse-server-example main.js afterSave downloadHistory');
    var entry = request.object;
    var bookId = entry.get('bookId');

    var booksClass = Parse.Object.extend('books');
    var query = new Parse.Query(booksClass);

    query.get(bookId, {success: function(book) {
        var currentDownloadCount = book.get('downloadCount') || 0;
        book.set('downloadCount', currentDownloadCount + 1);
        book.save(null, { useMasterKey: true }).then(
            function() {},
            function(error) {
                console.log("book.save failed: " + error);
                response.error("book.save failed: " + error);
            }
        );
    }, error: function(object, error) {
        console.log("get error: " + error);
    }});
});

// Return the books that should be shown in the default browse view.
// Currently this is those in the Featured bookshelf, followed by all the others.
// Each group is sorted alphabetically by title.
Parse.Cloud.define("defaultBooks", function(request, response) {
    console.log('parse-server-example main.js define defaultBooks function');
    var first = request.params.first;
    var count = request.params.count;
    var includeOutOfCirculation = request.params.includeOutOfCirculation;
    var allLicenses = request.params.allLicenses == true;
    var contentQuery = new Parse.Query("books");
    contentQuery.equalTo("tags", "bookshelf:Featured");
    if (!includeOutOfCirculation)
        contentQuery.containedIn('inCirculation', [true, undefined]);
    contentQuery.include("langPointers");
    contentQuery.include("uploader");
    if (!allLicenses)
        contentQuery.startsWith("license", "cc-");
    contentQuery.ascending("title");
    contentQuery.limit(1000); // max allowed...hoping no more than 1000 books in shelf??
    contentQuery.find({
        success: function(shelfBooks) {
            var results = [];
            var shelfIds = Object.create(null); // create an object with no properties to be a set
            var resultIndex = 0;
            for (var i = 0; i < shelfBooks.length; i++) {
                if (resultIndex >= first && resultIndex < first + count) {
                    results.push(shelfBooks[i]);
                }
                resultIndex++;
                shelfIds[shelfBooks[i].id] = true; // put in set
            }
            var skip = 0;
            // This function implements a query loop by calling itself inside each
            // promise fulfilment if more results are needed.
            var runQuery = function() {
                var allBooksQuery = new Parse.Query("books");
                if (!includeOutOfCirculation)
                    allBooksQuery.containedIn('inCirculation', [true, undefined]);
                allBooksQuery.include("langPointers");
                allBooksQuery.include("uploader");
                if (!allLicenses)
                    allBooksQuery.startsWith("license", "cc-");
                allBooksQuery.ascending("title");
                allBooksQuery.skip(skip); // skip the ones we already got
                allBooksQuery.find({
                    success: function (allBooks) {
                        skip += allBooks.length; // skip these ones next iteration
                        for (var i = 0; i < allBooks.length && resultIndex < first + count; i++) {
                            if (!(allBooks[i].id in shelfIds)) {
                                if (resultIndex >= first) {
                                    results.push(allBooks[i]);
                                }
                                resultIndex++;
                            }
                        }
                        if (allBooks.length == 0 || resultIndex >= first + count) {
                            // either we can't get any more, or we got all we need.
                            response.success(results);
                            return;
                        }
                        runQuery(); // launch another iteration.
                    },
                    error: function () {
                        response.error("failed to find all books");
                    }
                });
            }
            runQuery(); // start the recursive loop.
        },
        error: function() {
            response.error("failed to find books of featured shelf");
        }
    })
});


// This function is used to set up the fields used in the bloom library.
// Adding something here should be the ONLY way fields and classes are added to parse.com.
// After adding one, it is recommended that you first deploy the modified cloud code (see ReadMeParseComCloudCode.txt)
// to our 'test' project, run it, and verify that the result are as expected.
// Then try on the bloomlibrarysandbox (where you should also develop and test the
// functionality that uses the new fields).
// Finally deploy and run on the live database.
// Currently this will not delete fields or tables; if you want to do that it will have to be
// by hand.
// Run this function from a command line like this (with the appropriate keys for the application inserted)
// curl -X POST -H "X-Parse-Application-Id: <insert ID>"  -H "X-Parse-REST-API-Key: <insert REST key>" https://api.parse.com/1/functions/setupTables
Parse.Cloud.define("setupTables", function(request, response) {
    // Required BloomLibrary classes/fields
    // Note: code below currently requires that 'books' is first.
    // Current code supports only String, Boolean, Number, Date, Array, Pointer<_User/Book/appDetailsInLanguage>,
    // and Relation<books/appDetailsInLanguage>.
    // It would be easy to generalize the pointer/relation code provided we can organize so that classes that are
    // the target of relations or pointers occur before the fields targeting them.
    // This is because the way we 'create' a field is to create an instance of the class that has that field.
    // These instances can also be conveniently used as targets when creating instances of classes
    // that refer to them.
    console.log('parse-server-example main.js define setupTables function');
    var classes = [
        {
            name: "books",
            fields: [
                {name: "allTitles", type:"String"},
                {name: "baseUrl", type:"String"},
                {name: "bookInstanceId", type:"String"},
                {name: "bookLineage", type:"String"},
                {name: "bookOrder", type:"String"},
                {name: "bookletMakingIsAppropriate", type:"Boolean"},
                {name: "copyright", type:"String"},
                {name: "credits", type:"String"},
                {name: "currentTool", type:"String"},
                {name: "downloadCount", type:"Number"},
                {name: "downloadSource", type:"String"},
                {name: "experimental", type:"Boolean"},
                {name: "folio", type:"Boolean"},
                {name: "formatVersion", type:"String"},
                {name: "inCirculation", type: "Boolean"},
                {name: "isbn", type:"String"},
                {name: "langPointers", type:"Array"},
                {name: "languages", type:"Array"},
                {name: "librarianNote", type:"String"},
                {name: "license", type:"String"},
                {name: "licenseNotes", type:"String"},
                {name: "pageCount", type:"Number"},
                {name: "readerToolsAvailable", type:"Boolean"},
                {name: "search", type:"String"},
                {name: "suitableForMakingShells", type:"Boolean"},
                {name: "suitableForVernacularLibrary", type:"Boolean"},
                {name: "summary", type:"String"},
                {name: "tags", type:"Array"},
                {name: "thumbnail", type:"String"},
                {name: "title", type:"String"},
                {name: "tools", type:"Array"},
                {name: "updateSource", type:"String"},
                {name: "uploader", type:"Pointer<_User>"},
                {name: "lastUploaded", type:"Date"}
            ]
        },
        {
            name: "bookshelf",
            fields: [
                {name: "englishName", type:"String"},
                {name: "key", type:"String"},
                {name: "normallyVisible", type:"Boolean"},
                {name: "owner", type:"Pointer<_User>"}
            ]
        },
        {
            name: "downloadHistory",
            fields: [
                {name: "bookId", type: "String"},
                {name: "userIp", type: "String"},
                {name: "userName", type: "String"}
            ]
        },
        {
            name: "language",
            fields: [
                {name: "ethnologueCode", type: "String"},
                {name: "isoCode", type: "String"},
                {name: "name", type: "String"},
                {name: "englishName", type: "String"},
                //Usage count determined daily per Parse.com job
                {name: "usageCount", type: "Number"}
            ]
        },
        {
            name: "tag",
            fields: [
                {name: "name", type: "String"},
                //Usage count determined daily per Parse.com job
                {name: "usageCount", type: "Number"}
            ]
        },
        {
            name: "relatedBooks",
            fields: [
                {name: "books", type:"Array"}
            ]
        },
        {
            name: "appDetailsInLanguage",
            fields: [
                {name: "androidStoreLanguageIso", type:"String"},
                {name: "title", type:"String"},
                {name: "shortDescription", type:"String"},
                {name: "fullDescription", type:"String"}
            ]
        },
        {
            name: "appSpecification",
            fields: [
                {name: "bookVernacularLanguageIso", type:"String"},
                {name: "defaultStoreLanguageIso", type:"String"},
                {name: "buildEngineJobId", type:"String"},
                {name: "colorScheme", type:"String"},
                {name: "icon1024x1024", type:"String"},
                {name: "featureGraphic1024x500", type:"String"},
                {name: "details", type:"Relation<appDetailsInLanguage>"},
                {name: "owner", type:"Pointer<_User>"}
            ]
        },
        { // must come after the classes it references
            name: "booksInApp",
            fields: [
                {name: "app", type:"Pointer<appSpecification>"},
                {name: "book", type:"Pointer<books>"},
                {name: "index", type:"Integer"}
            ]
        }
    ];

    var ic = 0;
    var aUser = null;
    var aBook = null;
    var anApp = null;
    var aDetail = null;
    // If we're updating a 'live' table, typically we will have locked it down so
    // only with the master key can we add fields or classes.
    //Parse.Cloud.useMasterKey();

    var doOne = function() {
        var className = classes[ic].name;
        var parseClass = Parse.Object.extend(className);
        var instance = new parseClass();
        var val = null;
        var fields = classes[ic].fields;
        for (var ifld = 0; ifld < fields.length; ifld++) {
            var fieldName = fields[ifld].name;
            var fieldType = fields[ifld].type;
            switch (fieldType) {
                case "String":
                    instance.set(fieldName, "someString");
                    break;
                case "Date":
                    instance.set(fieldName, {"__type":"Date","iso":"2015-02-15T00:00:00.000Z"});
                    break;
                case "Boolean":
                    instance.set(fieldName, true);
                    break;
                case "Number":
                    instance.set(fieldName, 1);
                    break;
                case "Array":
                    instance.set(fieldName, ["one", "two"]);
                    break;
                case "Pointer<_User>":
                    instance.set(fieldName, aUser);
                    break;
                case "Pointer<books>":
                    // This and next could be generalized if we get a couple more. User would remain special.
                    instance.set(fieldName, aBook);
                    break;
                case "Pointer<appSpecification>":
                    instance.set(fieldName, anApp);
                    break;
                case "Relation<books>":
                    // This and next could be generalized if we have other kinds of relation one day.
                    var target = aBook;
                    var relation = instance.relation(fieldName);
                    relation.add(target);
                    break;
                case "Relation<appDetailsInLanguage>":
                    var target = aDetail;
                    var relation = instance.relation(fieldName);
                    relation.add(target);
                    break;
            }
        }
        instance.save(null, { useMasterKey: true,
            success: function (newObj) {
                // remember the new object so we can destroy it later, or use it as a relation target.
                classes[ic].parseObject = newObj;
                // if the class is one of the ones we reference in pointers or relations,
                // remember the appropriate instance for use in creating a sample.
                if (classes[ic].name == 'books') {
                    aBook = newObj;
                }
                else if (classes[ic].name == 'appSpecification') {
                    anApp = newObj;
                } else if (classes[ic].name == 'appDetailsInLanguage') {
                    aDetail = newObj;
                }
                ic++;
                if (ic < classes.length) {
                    doOne(); // recursive call to the main method to loop
                }
                else {
                    // Start a new recursive iteration to delete the objects we don't need.
                    ic = 0;
                    deleteOne();
                }
            },
            error: function (error) {
                console.log("instance.save failed: " + error);
                response.error("instance.save failed: " + error);
            }
        });
    };
    var deleteOne = function() {
        // Now we're done, the class and fields must exist; we don't actually want the instances
        var newObj = classes[ic].parseObject;
        newObj.destroy({success: function () {
            ic++;
            if (ic < classes.length) {
                deleteOne(); // recursive loop
            }
            else {
                cleanup();
            }
        },
            error: function (error) {
                response.error(error);
            }
        });
    };
    var cleanup = function() {
        // We've done the main job...now some details.
        var versionType = Parse.Object.extend("version");
        var query = new Parse.Query("version");
        query.find({
            success: function (results) {
                var version;
                if (results.length >= 1) {
                    // updating an existing project, already has version table and instance
                    version = results[0];
                }
                else {
                    version = new versionType();
                }
                version.set("minDesktopVersion", "2.0");
                version.save(null, { useMasterKey: true,
                    success: function () {
                        // Finally destroy the spurious user we made.
                        aUser.destroy({success: function () {
                            response.success("setupTables ran to completion.");                        },
                            error: function (error) {
                                response.error(error);
                            }
                        });
                    },
                    error: function (error) {
                        console.log("version.save failed: " + error);
                        response.error("version.save failed: " + error);
                    }
                })
            },
            error: function (error) {
                response.error(error);
            }
        });
    };
    // Create a user, temporarily, which we will delete later.
    // While debugging I got tired of having to manually remove previous "temporary" users,
    // hence each is now unique.
     var rand = parseInt((Math.random() * 10000), 10);
     Parse.User.signUp("zzDummyUserForSetupTables"+rand, "unprotected", {administrator: false}, {
        success: function(newUser) {
            aUser = newUser;
            doOne(); // start the recursion.
        },
        error: function (error) {
            response.error(error);
        }
    });

});
