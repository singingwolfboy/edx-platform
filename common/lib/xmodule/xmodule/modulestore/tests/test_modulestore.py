'''
Created on Mar 25, 2013

@author: dmitchell
'''
from xmodule.course_module import CourseDescriptor
from xmodule.modulestore.exceptions import InsufficientSpecificationError, ItemNotFoundError
from xmodule.modulestore.locator import CourseLocator, BlockLocator, VersionTree, DescriptorLocator
import datetime
import subprocess
import unittest
import copy
import uuid
from importlib import import_module
import os
import re
from xblock.core import Scope


class SplitModuleTest(unittest.TestCase):
    '''
    The base set of tests manually populates a db w/ courses which have
    versions. It creates unique collection names and removes them after all
    tests finish.
    '''
    # Snippet of what would be in the django settings envs file
    modulestore_options = {
        'default_class': 'xmodule.raw_module.RawDescriptor',
        'host': 'localhost',
        'db': 'test_xmodule',
        'collection': 'modulestore{0}'.format(uuid.uuid4().hex),
        'fs_root': ''
    }

    draft_aware = copy.copy(modulestore_options)
    draft_aware['draft_aware'] = True

    MODULESTORE = {
        'default': {
            'ENGINE': 'xmodule.modulestore.split_mongo.SplitMongoModuleStore',
            'OPTIONS': draft_aware
            },
        'direct': {
            'ENGINE': 'xmodule.modulestore.split_mongo.SplitMongoModuleStore',
            'OPTIONS': modulestore_options
        }
    }

    _MODULESTORES = {}

    @classmethod
    def setUpClass(cls):
        '''
        Loads the initial data into the db ensuring the collection name is
        unique.
        '''
        dbname = cls.MODULESTORE['default']['OPTIONS']['db']
        collection_prefix = cls.MODULESTORE['default']['OPTIONS']['collection']
        # TODO is it safe to assume mitx will be on the path?
        match = re.search(r'(.*?/mitx)(?:$|/)', os.getcwd())
        cwd = match.group(1) + '/'
        processes = [
            # /usr/local/bin/mongoimport
            subprocess.Popen(['/usr/local/bin/mongoimport', '-d', dbname, '-c',
                collection_prefix + '.' + collection, '--jsonArray',
                '--file',
                cwd + 'fixtures/splitmongo_json/' + collection + '.json'])
                for collection in ('active_versions', 'structures', 'definitions')]
        for p in processes:
            if p.wait() != 0:
                raise Exception("DB did not init correctly")

    @classmethod
    def tearDownClass(cls):
        for collection in ('active_versions', 'structures', 'definitions'):
            modulestore().db.drop_collection('modulestore.' + collection)

    def findByIdInResult(self, collection, _id):
        '''
        Result is a collection of descriptors. Find the one who's block id
        matches the _id.
        '''
        for element in collection:
            if element.location.block_id == _id:
                return element


class SplitModuleCourseTests(SplitModuleTest):
    '''
    Course CRUD operation tests
    '''
    def test_get_courses(self):
        courses = modulestore().get_courses()
        # should have gotten 3 draft courses
        self.assertEqual(len(courses), 3, "Wrong number of courses")
        # check metadata -- NOTE no promised order
        course = self.findByIdInResult(courses, "head12345")
        self.assertEqual(course.location.course_id, "GreekHero")
        self.assertEqual(course.location.version_guid, "v12345d",
            "course version mismatch")
        self.assertEqual(course.category, 'course', 'wrong category')
        self.assertEqual(len(course.tabs), 6, "wrong number of tabs")
        self.assertEqual(course.display_name, "The Ancient Greek Hero",
            "wrong display name")
        self.assertEqual(course.advertised_start, "Fall 2013",
            "advertised_start")
        self.assertEqual(len(course.children), 3,
            "children")
        self.assertEqual(course.definition_locator.def_id, "head12345_12")
        # check dates and graders--forces loading of descriptor
        self.assertEqual(course.cms.edited_by, "testassist@edx.org",
            course.cms.edited_by)
        self.assertDictEqual(course.grade_cutoffs, {"Pass": 0.45},
            course.grade_cutoffs)

        # query w/ revision qualifier (both draft and published)
        courses_draft = modulestore().get_courses(revision='draft')
        self.assertEqual(len(courses_draft), len(courses),
            "Wrong number of courses")
        for course in courses_draft:
            self.assertIsNotNone(self.findByIdInResult(courses,
                course.location.block_id),
                "Cannot find {course.location.block_id}".format(
                    course=course))
        courses_draft = modulestore('default').get_courses()
        self.assertEqual(len(courses_draft), len(courses),
            "Wrong number of courses")
        for course in courses_draft:
            self.assertIsNotNone(self.findByIdInResult(courses,
                course.location.block_id),
                "Cannot find {course.location.block_id}".format(
                    course=course))

        courses_published = modulestore().get_courses(revision='published')
        self.assertEqual(len(courses_published), 1, len(courses_published))
        course = self.findByIdInResult(courses_published, "head23456")
        self.assertIsNotNone(course, "published courses")
        self.assertEqual(course.location.course_id, "wonderful")
        self.assertEqual(course.location.version_guid, "v23456p",
            course.location.version_guid)
        self.assertEqual(course.category, 'course', 'wrong category')
        self.assertEqual(len(course.tabs), 4, "wrong number of tabs")
        self.assertEqual(course.display_name, "The most wonderful course",
            course.display_name)
        self.assertIsNone(course.advertised_start)
        self.assertEqual(len(course.children), 0,
            "children")
        courses_direct = modulestore('direct').get_courses()
        self.assertEqual(len(courses_direct), 1, len(courses_direct))
        self.assertEqual(courses_direct[0].location,
            courses_published[0].location)

        # query w/ search criteria
        courses = modulestore().get_courses(qualifiers={'org': 'testx'})
        self.assertEqual(len(courses), 2)
        self.assertIsNotNone(self.findByIdInResult(courses, "head12345"))
        self.assertIsNotNone(self.findByIdInResult(courses, "head23456"))

        courses = modulestore().get_courses(
            qualifiers={'edited_on': {"$lt": datetime.datetime(2013, 3, 28, 15)}})
        self.assertEqual(len(courses), 2)

        courses = modulestore().get_courses(qualifiers={'org': 'testx',
            "prettyid": "test_course"})
        self.assertEqual(len(courses), 1)
        self.assertIsNotNone(self.findByIdInResult(courses, "head12345"))

        courses = modulestore().get_courses(
            qualifiers={'publishedVersion': {'$ne': None}})
        self.assertEqual(len(courses), 1)
        self.assertIsNotNone(self.findByIdInResult(courses, "head23456"))

    def test_get_course(self):
        '''
        Test the various calling forms for get_course
        '''
        locator = CourseLocator(version_guid='v12345d1')
        course = modulestore().get_course(locator)
        self.assertIsNone(course.location.course_id)
        self.assertEqual(course.location.version_guid, "v12345d1")
        self.assertEqual(course.category, 'course')
        self.assertEqual(len(course.tabs), 6)
        self.assertEqual(course.display_name, "The Ancient Greek Hero")
        self.assertIsNone(course.advertised_start)
        self.assertEqual(len(course.children), 0)
        self.assertEqual(course.definition_locator.def_id, "head12345_11")
        # check dates and graders--forces loading of descriptor
        self.assertEqual(course.cms.edited_by, "testassist@edx.org")
        self.assertDictEqual(course.grade_cutoffs, {"Pass": 0.55})

        locator = CourseLocator(course_id='GreekHero')
        course = modulestore().get_course(locator)
        self.assertEqual(course.location.course_id, "GreekHero")
        self.assertEqual(course.location.version_guid, "v12345d")
        self.assertEqual(course.category, 'course')
        self.assertEqual(len(course.tabs), 6)
        self.assertEqual(course.display_name, "The Ancient Greek Hero")
        self.assertEqual(course.advertised_start, "Fall 2013")
        self.assertEqual(len(course.children), 3)
        # check dates and graders--forces loading of descriptor
        self.assertEqual(course.cms.edited_by, "testassist@edx.org")
        self.assertDictEqual(course.grade_cutoffs, {"Pass": 0.45})

        locator = CourseLocator(course_id='GreekHero', revision='draft')
        course = modulestore().get_course(locator)
        self.assertEqual(course.location.course_id, "GreekHero")
        self.assertEqual(course.location.version_guid, "v12345d")

        locator = CourseLocator(course_id='wonderful', revision='published')
        course = modulestore().get_course(locator)
        self.assertEqual(course.location.course_id, "wonderful")
        self.assertEqual(course.location.version_guid, "v23456p")

        locator = CourseLocator(course_id='wonderful')
        course = modulestore().get_course(locator, revision='published')
        self.assertEqual(course.location.course_id, "wonderful")
        self.assertEqual(course.location.version_guid, "v23456p")

        locator = CourseLocator(course_id='wonderful')
        course = modulestore().get_course(locator, revision='draft')
        self.assertEqual(course.location.version_guid, "v23456d")

        # Now negative testing
        self.assertRaises(InsufficientSpecificationError,
            modulestore().get_course, CourseLocator())
        self.assertRaises(ItemNotFoundError,
            modulestore().get_course, CourseLocator(course_id='nosuchthing'))
        self.assertRaises(ItemNotFoundError,
            modulestore().get_course,
            CourseLocator(course_id='GreekHero', revision='published'))

    def test_course_successors(self):
        """
        get_course_successors(course_locator, version_history_depth=1, revision=None)
        """
        locator = CourseLocator(version_guid="v12345d0")
        result = modulestore().get_course_successors(locator)
        self.assertIsInstance(result, VersionTree)
        self.assertIsNone(result.locator.course_id)
        self.assertEqual(result.locator.version_guid, "v12345d0")
        self.assertEqual(len(result.children), 1)
        self.assertEqual(result.children[0].locator.version_guid, "v12345d1")
        self.assertEqual(len(result.children[0].children), 0, "descended more than one level")
        result = modulestore().get_course_successors(locator, version_history_depth=2)
        self.assertEqual(len(result.children), 1)
        self.assertEqual(result.children[0].locator.version_guid, "v12345d1")
        self.assertEqual(len(result.children[0].children), 1)
        result = modulestore().get_course_successors(locator, version_history_depth=99)
        self.assertEqual(len(result.children), 1)
        self.assertEqual(result.children[0].locator.version_guid, "v12345d1")
        self.assertEqual(len(result.children[0].children), 1)


class SplitModuleItemTests(SplitModuleTest):
    '''
    Item read tests including inheritance
    '''
    def test_has_item(self):
        '''
        has_item(BlockLocator, revision)
        '''
        # positive tests of various forms
        locator = BlockLocator(version_guid='v12345d1', block_id='head12345')
        self.assertTrue(modulestore().has_item(locator),
            "couldn't find in v12345d1")

        locator = BlockLocator(course_id='GreekHero', block_id='head12345')
        self.assertTrue(modulestore().has_item(locator),
            "couldn't find in 12345")
        self.assertTrue(modulestore().has_item(locator, revision='draft'),
            "couldn't find in draft 12345")
        self.assertFalse(modulestore().has_item(locator, revision='published'),
            "found in published 12345")
        locator.revision = 'draft'
        self.assertTrue(modulestore().has_item(locator),
            "not found in draft 12345")

        # not a course obj
        locator = BlockLocator(course_id='GreekHero', block_id='chapter1')
        self.assertTrue(modulestore().has_item(locator),
            "couldn't find chapter1")

        # in published course
        locator = BlockLocator(course_id="wonderful", block_id="head23456")
        self.assertTrue(modulestore().has_item(locator, revision='published'),
            "couldn't find in 23456")
        locator.revision = 'published'
        self.assertTrue(modulestore().has_item(locator),
            "couldn't find in 23456")

        # negative tests--not found
        # no such course or block
        locator = BlockLocator(course_id="doesnotexist", block_id="head23456")
        self.assertFalse(modulestore().has_item(locator))
        locator = BlockLocator(course_id="wonderful", block_id="doesnotexist")
        self.assertFalse(modulestore().has_item(locator))

        # negative tests--insufficient specification
        self.assertRaises(InsufficientSpecificationError,
            modulestore().has_item, BlockLocator())
        self.assertRaises(InsufficientSpecificationError,
            modulestore().has_item, BlockLocator(version_guid='v12345d1'))
        self.assertRaises(InsufficientSpecificationError,
            modulestore().has_item, BlockLocator(course_id='GreekHero'))
        self.assertRaises(InsufficientSpecificationError,
            modulestore().has_item, BlockLocator(block_id='head12345'))

    def test_get_instance(self):
        '''
        get_instance(blocklocator, revision)
        '''
        # positive tests of various forms
        locator = BlockLocator(version_guid='v12345d1', block_id='head12345')
        block = modulestore().get_instance(locator)
        self.assertIsInstance(block, CourseDescriptor)

        locator = BlockLocator(course_id='GreekHero', block_id='head12345')
        block = modulestore().get_instance(locator)
        self.assertEqual(block.location.course_id, "GreekHero")
        # look at this one in detail
        self.assertEqual(len(block.tabs), 6, "wrong number of tabs")
        self.assertEqual(block.display_name, "The Ancient Greek Hero")
        self.assertEqual(block.advertised_start, "Fall 2013")
        self.assertEqual(len(block.children), 3)
        self.assertEqual(block.definition_locator.def_id, "head12345_12")
        # check dates and graders--forces loading of descriptor
        self.assertEqual(block.cms.edited_by, "testassist@edx.org",
            block.cms.edited_by)
        self.assertDictEqual(block.grade_cutoffs, {"Pass": 0.45},
            block.grade_cutoffs)

        # try to look up other revisions
        self.assertIsInstance(
            modulestore().get_instance(locator, revision='draft'),
            CourseDescriptor)
        self.assertRaises(ItemNotFoundError,
            modulestore().get_instance, locator, revision='published')
        locator.revision = 'draft'
        self.assertIsInstance(modulestore().get_instance(locator),
            CourseDescriptor)

        # not a course obj
        locator = BlockLocator(course_id='GreekHero', block_id='chapter1')
        block = modulestore().get_instance(locator)
        self.assertEqual(block.location.course_id, "GreekHero")
        self.assertEqual(block.category, 'chapter')
        self.assertEqual(block.definition_locator.def_id, "chapter12345_1")
        self.assertEqual(block.display_name, "Hercules")
        self.assertEqual(block.cms.edited_by, "testassist@edx.org")

        # in published course
        locator = BlockLocator(course_id="wonderful", block_id="head23456")
        self.assertIsInstance(
            modulestore().get_instance(locator, revision='published'),
            CourseDescriptor)
        locator.revision = 'published'
        self.assertIsInstance(modulestore().get_instance(locator),
            CourseDescriptor)

        # negative tests--not found
        # no such course or block
        locator = BlockLocator(course_id="doesnotexist", block_id="head23456")
        self.assertRaises(ItemNotFoundError,
            modulestore().get_instance, locator)
        locator = BlockLocator(course_id="wonderful", block_id="doesnotexist")
        self.assertRaises(ItemNotFoundError,
            modulestore().get_instance, locator)

        # negative tests--insufficient specification
        self.assertRaises(InsufficientSpecificationError,
            modulestore().get_instance, BlockLocator())
        self.assertRaises(InsufficientSpecificationError,
            modulestore().get_instance, BlockLocator(version_guid='v12345d1'))
        self.assertRaises(InsufficientSpecificationError,
            modulestore().get_instance, BlockLocator(course_id='GreekHero'))
        self.assertRaises(InsufficientSpecificationError,
            modulestore().get_instance, BlockLocator(block_id='head12345'))

    # pylint: disable=W0212
    def test_matching(self):
        '''
        test the block and value matches help functions
        '''
        self.assertTrue(modulestore()._value_matches('help', 'help'))
        self.assertFalse(modulestore()._value_matches('help', 'Help'))
        self.assertTrue(modulestore()._value_matches(['distract', 'help', 'notme'], 'help'))
        self.assertFalse(modulestore()._value_matches(['distract', 'Help', 'notme'], 'help'))
        self.assertFalse(modulestore()._value_matches({'field' : ['distract', 'Help', 'notme']}, {'field' : 'help'}))
        self.assertFalse(modulestore()._value_matches(['distract', 'Help', 'notme'], {'field' : 'help'}))
        self.assertTrue(modulestore()._value_matches(
            {'field' : ['distract', 'help', 'notme'],
                'irrelevant' : 2},
            {'field' : 'help'}))
        self.assertTrue(modulestore()._value_matches('I need some help', {'$regex' : 'help'}))
        self.assertTrue(modulestore()._value_matches(['I need some help', 'today'], {'$regex' : 'help'}))
        self.assertFalse(modulestore()._value_matches('I need some help', {'$regex' : 'Help'}))
        self.assertFalse(modulestore()._value_matches(['I need some help', 'today'], {'$regex' : 'Help'}))

        self.assertTrue(modulestore()._block_matches({'a' : 1, 'b' : 2}, {'a' : 1}))
        self.assertTrue(modulestore()._block_matches({'a' : 1, 'b' : 2}, {'c' : None}))
        self.assertTrue(modulestore()._block_matches({'a' : 1, 'b' : 2}, {'a' : 1, 'c' : None}))
        self.assertFalse(modulestore()._block_matches({'a' : 1, 'b' : 2}, {'a' : 2}))
        self.assertFalse(modulestore()._block_matches({'a' : 1, 'b' : 2}, {'c' : 1}))
        self.assertFalse(modulestore()._block_matches({'a' : 1, 'b' : 2}, {'a' : 1, 'c' : 1}))

    def test_get_items(self):
        '''
        get_items(locator, qualifiers, [revision])
        '''
        locator = CourseLocator(version_guid="v12345d")
        # get all modules
        matches = modulestore().get_items(locator, {})
        self.assertEqual(len(matches), 6)
        matches = modulestore().get_items(locator, {'category' : 'chapter'})
        self.assertEqual(len(matches), 3)
        matches = modulestore().get_items(locator, {'category' : 'garbage'})
        self.assertEqual(len(matches), 0)
        matches = modulestore().get_items(locator, {'category' : 'chapter',
            'metadata' : {'display_name' : {'$regex' : 'Hera'}}})
        self.assertEqual(len(matches), 2)

        matches = modulestore().get_items(locator, {'children' : 'chapter2'})
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].location.block_id, 'head12345')

    def test_get_parents(self):
        '''
        get_parent_locations(locator, [block_id], [revision]): [BlockLocator]
        '''
        locator = CourseLocator(course_id="GreekHero")
        parents = modulestore().get_parent_locations(locator, block_id='chapter1')
        self.assertEqual(len(parents), 1)
        self.assertEqual(parents[0].block_id, 'head12345')
        self.assertEqual(parents[0].course_id, "GreekHero")
        locator.block_id = 'chapter2'
        parents = modulestore().get_parent_locations(locator)
        self.assertEqual(len(parents), 1)
        self.assertEqual(parents[0].block_id, 'head12345')
        parents = modulestore().get_parent_locations(locator, block_id='nosuchblock')
        self.assertEqual(len(parents), 0)


class TestItemCrud(SplitModuleTest):
    """
    Test create update and delete of items
    """
    # TODO do I need to test this case which I believe won't work:
    #  1) fetch a course and some of its blocks
    #  2) do a series of CRUD operations on those previously fetched elements
    # The problem here will be that the version_guid of the items will be the version at time of fetch.
    # Each separate save will change the head version; so, the 2nd piecemeal change will flag the version
    # conflict. That is, if versions are v0..vn and start as v0 in initial fetch, the first CRUD op will
    # say it's changing an object from v0, splitMongo will process it and make the current head v1, the next
    # crud op will pass in its v0 element and splitMongo will flag the version conflict.
    # What I don't know is how realistic this test is and whether to wrap the modulestore with a higher level
    # transactional operation which manages the version change or make the threading cache reason out whether or
    # not the changes are independent and additive and thus non-conflicting.
    # A use case I expect is
    # (client) change this metadata
    # (server) done, here's the new info which, btw, updates the course version to v1
    # (client) add these children to this other node (which says it came from v0 or
    #          will the client have refreshed the version before doing the op?)
    # In this case, having a server side transactional model won't help b/c the bug is a long-transaction on the
    # on the client where it would be a mistake for the server to assume anything about client consistency. The best
    # the server could do would be to see if the parent's children changed at all since v0.
    def test_create_minimal_item(self):
        """
        create_item(course_or_parent_locator, category, user, definition_locator=None, new_def_data=None,
        metadata=None): new_desciptor
        """
        # grab link to course to ensure new versioning works
        locator = CourseLocator(course_id="GreekHero")
        premod_course = modulestore().get_course(locator)
        premod_time = datetime.datetime.utcnow()
        # add minimal one w/o a parent
        category = 'sequential'
        new_module = modulestore().create_item(locator, category, 'user123',
            metadata={'display_name': 'new sequential'})
        # check that course version changed and course's previous is the other one
        self.assertEqual(new_module.location.course_id, "GreekHero")
        self.assertNotEqual(new_module.location.version_guid, premod_course.location.version_guid)
        self.assertIsNone(locator.version_guid, "Version inadvertently filled in")
        current_course = modulestore().get_course(locator)
        self.assertEqual(new_module.location.version_guid, current_course.location.version_guid)

        history_info = modulestore().get_course_history_info(current_course.location)
        self.assertEqual(history_info['previous_version'], premod_course.location.version_guid)
        self.assertEqual(history_info['original_version'], "v12345d0")
        self.assertEqual(history_info['edited_by'], "user123")
        self.assertGreaterEqual(history_info['edited_on'], premod_time)
        self.assertLessEqual(history_info['edited_on'], datetime.datetime.utcnow())
        # check block's info: category, definition_locator, and display_name
        self.assertEqual(new_module.category, 'sequential')
        self.assertIsNotNone(new_module.definition_locator)
        self.assertEqual(new_module.display_name, 'new sequential')
        # check that block does not exist in previous version
        locator = BlockLocator(version_guid=premod_course.location.version_guid,
            block_id=new_module.location.block_id)
        self.assertRaises(ItemNotFoundError, modulestore().get_instance, locator)

    def test_create_parented_item(self):
        """
        Test create_item w/ specifying the parent of the new item
        """
        locator = BlockLocator(course_id="wonderful", block_id="head23456")
        premod_course = modulestore().get_course(locator)
        category = 'chapter'
        new_module = modulestore().create_item(locator, category, 'user123',
            metadata={'display_name': 'new chapter'},
            definition_locator=DescriptorLocator("chapter12345_2"))
        # check that course version changed and course's previous is the other one
        self.assertNotEqual(new_module.location.version_guid, premod_course.location.version_guid)
        parent = modulestore().get_instance(locator)
        self.assertIn(new_module.location.block_id, parent.children)
        self.assertEqual(new_module.definition_locator.def_id, "chapter12345_2")

    def test_unique_naming(self):
        """
        Check that 2 modules of same type get unique block_ids. Also check that if creation provides
        a definition id and new def data that it branches the definition in the db.
        Actually, this tries to test all create_item features not tested above.
        """
        locator = BlockLocator(course_id="contender", block_id="head345679")
        category = 'problem'
        premod_time = datetime.datetime.utcnow()
        new_payload = "<problem>empty</problem>"
        new_module = modulestore().create_item(locator, category, 'anotheruser',
            metadata={'display_name': 'problem 1'}, new_def_data=new_payload)
        another_payload = "<problem>not empty</problem>"
        another_module = modulestore().create_item(locator, category, 'anotheruser',
            metadata={'display_name': 'problem 2'},
            definition_locator=DescriptorLocator("problem12345_3_1"),
            new_def_data=another_payload)
        # check that course version changed and course's previous is the other one
        parent = modulestore().get_instance(locator)
        self.assertNotEqual(new_module.location.block_id, another_module.location.block_id)
        self.assertIn(new_module.location.block_id, parent.children)
        self.assertIn(another_module.location.block_id, parent.children)
        self.assertEqual(new_module.data, new_payload)
        self.assertEqual(another_module.data, another_payload)
        # check definition histories
        new_history = modulestore().get_definition_history_info(new_module.definition_locator)
        self.assertIsNone(new_history['previous_version'])
        self.assertEqual(new_history['original_version'], new_module.definition_locator.def_id)
        self.assertEqual(new_history['edited_by'], "anotheruser")
        self.assertLessEqual(new_history['edited_on'], datetime.datetime.utcnow())
        self.assertGreaterEqual(new_history['edited_on'], premod_time)
        another_history = modulestore().get_definition_history_info(another_module.definition_locator)
        self.assertEqual(another_history['previous_version'], 'problem12345_3_1')
    # TODO check that default fields are set

    def test_update_metadata(self):
        """
        test updating an items metadata ensuring the definition doesn't version but the course does if it should
        """
        locator = BlockLocator(course_id="GreekHero", block_id="problem3_2")
        problem = modulestore().get_instance(locator)
        pre_def_id = problem.definition_locator.def_id
        pre_version_guid = problem.location.version_guid
        self.assertIsNotNone(pre_def_id)
        self.assertIsNotNone(pre_version_guid)
        premod_time = datetime.datetime.utcnow()
        self.assertNotEqual(problem.max_attempts, 4, "Invalidates rest of test")

        problem.max_attempts = 4
        updated_problem = modulestore().update_item(problem, 'changeMaven')
        # check that course version changed and course's previous is the other one
        self.assertEqual(updated_problem.definition_locator.def_id, pre_def_id)
        self.assertNotEqual(updated_problem.location.version_guid, pre_version_guid)
        self.assertEqual(updated_problem.max_attempts, 4)
        # refetch to ensure original didn't change
        original_location = BlockLocator(version_guid=pre_version_guid,
            block_id=problem.location.block_id)
        problem = modulestore().get_instance(original_location)
        self.assertNotEqual(problem.max_attempts, 4, "original changed")

        current_course = modulestore().get_course(locator)
        self.assertEqual(updated_problem.location.version_guid, current_course.location.version_guid)

        history_info = modulestore().get_course_history_info(current_course.location)
        self.assertEqual(history_info['previous_version'], pre_version_guid)
        self.assertEqual(history_info['original_version'], "v12345d0")
        self.assertEqual(history_info['edited_by'], "changeMaven")
        self.assertGreaterEqual(history_info['edited_on'], premod_time)
        self.assertLessEqual(history_info['edited_on'], datetime.datetime.utcnow())

    def test_update_children(self):
        """
        test updating an item's children ensuring the definition doesn't version but the course does if it should
        """
        locator = BlockLocator(course_id="GreekHero", block_id="chapter3")
        block = modulestore().get_instance(locator)
        pre_def_id = block.definition_locator.def_id
        pre_version_guid = block.location.version_guid

        # reorder children
        self.assertGreater(len(block.children), 0, "meaningless test")
        moved_child = block.children.pop()
        updated_problem = modulestore().update_item(block, 'childchanger')
        # check that course version changed and course's previous is the other one
        self.assertEqual(updated_problem.definition_locator.def_id, pre_def_id)
        self.assertNotEqual(updated_problem.location.version_guid, pre_version_guid)
        self.assertEqual(updated_problem.children, block.children)
        self.assertNotIn(moved_child, updated_problem.children)
        locator.block_id = "chapter1"
        other_block = modulestore().get_instance(locator)
        other_block.children.append(moved_child)
        other_updated = modulestore().update_item(other_block, 'childchanger')
        self.assertIn(moved_child, other_updated.children)

    def test_update_definition(self):
        """
        test updating an item's definition: ensure it gets versioned as well as the course getting versioned
        """
        locator = BlockLocator(course_id="GreekHero", block_id="head12345")
        block = modulestore().get_instance(locator)
        pre_def_id = block.definition_locator.def_id
        pre_version_guid = block.location.version_guid

        block.grading_policy['GRADER'][0]['min_count'] = 13
        updated_block = modulestore().update_item(block, 'definition_changer')

        self.assertNotEqual(updated_block.definition_locator.def_id, pre_def_id)
        self.assertNotEqual(updated_block.location.version_guid, pre_version_guid)
        self.assertEqual(updated_block.grading_policy['GRADER'][0]['min_count'], 13)

    def test_update_manifold(self):
        """
        Test updating metadata, children, and definition in a single call ensuring all the versioning occurs
        """
        # first add 2 children to the course for the update to manipulate
        locator = BlockLocator(course_id="contender", block_id="head345679")
        category = 'problem'
        new_payload = "<problem>empty</problem>"
        modulestore().create_item(locator, category, 'test_update_manifold',
            metadata={'display_name': 'problem 1'}, new_def_data=new_payload)
        another_payload = "<problem>not empty</problem>"
        modulestore().create_item(locator, category, 'test_update_manifold',
            metadata={'display_name': 'problem 2'},
            definition_locator=DescriptorLocator("problem12345_3_1"),
            new_def_data=another_payload)
        # pylint: disable=W0212
        modulestore()._clear_cache()

        # now begin the test
        block = modulestore().get_instance(locator)
        pre_def_id = block.definition_locator.def_id
        pre_version_guid = block.location.version_guid

        self.assertNotEqual(block.grading_policy['GRADER'][0]['min_count'], 13)
        block.grading_policy['GRADER'][0]['min_count'] = 13
        block.children = block.children[1:] + [block.children[0]]
        block.advertised_start = "Soon"

        updated_block = modulestore().update_item(block, "test_update_manifold")
        self.assertNotEqual(updated_block.definition_locator.def_id, pre_def_id)
        self.assertNotEqual(updated_block.location.version_guid, pre_version_guid)
        self.assertEqual(updated_block.grading_policy['GRADER'][0]['min_count'], 13)
        self.assertEqual(updated_block.children[0], block.children[0])
        self.assertEqual(updated_block.advertised_start, "Soon")


class TestCourseCreation(SplitModuleTest):
    """
    Test create_course, duh :-)
    """
    def test_simple_creation(self):
        """
        The simplest case but probing all expected results from it.
        """
        pre_time = datetime.datetime.utcnow()
        new_course = modulestore().create_course('test_org', 'test_course', 'create_user')
        new_locator = new_course.location
        # check index entry
        index_info = modulestore().get_course_index_info(new_locator)
        self.assertEqual(index_info['org'], 'test_org')
        self.assertEqual(index_info['prettyid'], 'test_course')
        self.assertGreaterEqual(index_info["edited_on"], pre_time)
        self.assertLessEqual(index_info["edited_on"], datetime.datetime.utcnow())
        self.assertEqual(index_info['edited_by'], 'create_user')
        # check structure info
        structure_info = modulestore().get_course_history_info(new_locator)
        self.assertEqual(structure_info['original_version'], index_info['draftVersion'])
        self.assertIsNone(structure_info['previous_version'])
        self.assertGreaterEqual(structure_info["edited_on"], pre_time)
        self.assertLessEqual(structure_info["edited_on"], datetime.datetime.utcnow())
        self.assertEqual(structure_info['edited_by'], 'create_user')
        # check the returned course object
        self.assertIsInstance(new_course, CourseDescriptor)
        self.assertEqual(new_course.category, 'course')
        self.assertFalse(new_course.show_calculator)
        self.assertTrue(new_course.allow_anonymous)
        self.assertEqual(len(new_course.children), 0)
        self.assertEqual(new_course.cms.edited_by, "create_user")
        self.assertEqual(len(new_course.grading_policy['GRADER']), 4)
        self.assertDictEqual(new_course.grade_cutoffs, {"Pass": 0.5})

    def test_cloned_course(self):
        """
        Test making a course which points to an existing draft and published but not making any changes to either.
        """
        pre_time = datetime.datetime.utcnow()
        original_locator = CourseLocator(course_id="wonderful")
        original_index = modulestore().get_course_index_info(original_locator)
        new_draft = modulestore().create_course('leech', 'best_course', 'leech_master', id_root='best',
            draft_version=original_index['draftVersion'], published_version=original_index['publishedVersion'])
        new_draft_locator = new_draft.location
        self.assertRegexpMatches(new_draft_locator.course_id, r'best.*')
        # the edited_by and other meta fields on the new course will be the original author not this one
        self.assertEqual(new_draft.cms.edited_by, 'test@edx.org')
        self.assertLess(new_draft.cms.edited_on, pre_time)
        self.assertEqual(new_draft.location.version_guid, original_index['draftVersion'])
        # however the edited_by and other meta fields on course_index will be this one
        new_index = modulestore().get_course_index_info(new_draft_locator)
        self.assertGreaterEqual(new_index["edited_on"], pre_time)
        self.assertLessEqual(new_index["edited_on"], datetime.datetime.utcnow())
        self.assertEqual(new_index['edited_by'], 'leech_master')

        new_published_locator = CourseLocator(course_id=new_draft_locator.course_id, revision='published')
        new_published = modulestore().get_course(new_published_locator)
        self.assertEqual(new_published.cms.edited_by, 'test@edx.org')
        self.assertLess(new_published.cms.edited_on, pre_time)
        self.assertEqual(new_published.location.version_guid, original_index['publishedVersion'])

        # changing this course will not change the original course
        # using new_draft.location will insert the chapter under the course root
        new_item = modulestore().create_item(new_draft.location, 'chapter', 'leech_master',
            metadata={'display_name': 'new chapter'})
        new_draft_locator.version_guid = None
        new_index = modulestore().get_course_index_info(new_draft_locator)
        self.assertNotEqual(new_index['draftVersion'], original_index['draftVersion'])
        new_draft = modulestore().get_course(new_draft_locator)
        self.assertEqual(new_item.cms.edited_by, 'leech_master')
        self.assertGreaterEqual(new_item.cms.edited_on, pre_time)
        self.assertNotEqual(new_item.location.version_guid, original_index['draftVersion'])
        self.assertNotEqual(new_draft.location.version_guid, original_index['draftVersion'])
        structure_info = modulestore().get_course_history_info(new_draft_locator)
        self.assertGreaterEqual(structure_info["edited_on"], pre_time)
        self.assertLessEqual(structure_info["edited_on"], datetime.datetime.utcnow())
        self.assertEqual(structure_info['edited_by'], 'leech_master')

        original_course = modulestore().get_course(original_locator)
        self.assertEqual(original_course.location.version_guid, original_index['draftVersion'])
        self.assertFalse(modulestore().has_item(BlockLocator(original_locator, block_id=new_item.location.block_id)))

    def test_derived_course(self):
        """
        Create a new course which overrides metadata and course_data
        """
        pre_time = datetime.datetime.utcnow()
        original_locator = CourseLocator(course_id="contender")
        original = modulestore().get_course(original_locator)
        original_index = modulestore().get_course_index_info(original_locator)
        data_payload = {}
        metadata_payload = {}
        for field in original.fields:
            if field.scope == Scope.content:
                data_payload[field.name] = getattr(original, field.name)
            elif field.scope == Scope.settings:
                metadata_payload[field.name] = getattr(original, field.name)
        data_payload['grading_policy']['GRADE_CUTOFFS'] = {'A': .9, 'B': .8, 'C': .65}
        metadata_payload['display_name'] = 'Derivative'
        new_draft = modulestore().create_course('leech', 'derivative', 'leech_master', id_root='counter',
            draft_version=original_index['draftVersion'],
            course_data=data_payload, metadata=metadata_payload)
        new_draft_locator = new_draft.location
        self.assertRegexpMatches(new_draft_locator.course_id, r'counter.*')
        # the edited_by and other meta fields on the new course will be the original author not this one
        self.assertEqual(new_draft.cms.edited_by, 'leech_master')
        self.assertGreaterEqual(new_draft.cms.edited_on, pre_time)
        self.assertNotEqual(new_draft.location.version_guid, original_index['draftVersion'])
        # however the edited_by and other meta fields on course_index will be this one
        new_index = modulestore().get_course_index_info(new_draft_locator)
        self.assertGreaterEqual(new_index["edited_on"], pre_time)
        self.assertLessEqual(new_index["edited_on"], datetime.datetime.utcnow())
        self.assertEqual(new_index['edited_by'], 'leech_master')
        self.assertEqual(new_draft.display_name, metadata_payload['display_name'])
        self.assertDictEqual(new_draft.grading_policy['GRADE_CUTOFFS'],
            data_payload['grading_policy']['GRADE_CUTOFFS'])


class TestInheritance(SplitModuleTest):
    """
    Test the metadata inheritance mechanism.
    """
    def test_inheritance(self):
        """
        The actual test
        """
        # Note, not testing value where defined (course) b/c there's no
        # defined accessor for it on CourseDescriptor.
        locator = BlockLocator(course_id="GreekHero", block_id="problem3_2")
        node = modulestore().get_instance(locator)
        # inherited
        self.assertEqual(node.graceperiod, datetime.timedelta(hours=2))
        locator = BlockLocator(course_id="GreekHero", block_id="problem1")
        node = modulestore().get_instance(locator)
        # overridden
        self.assertEqual(node.graceperiod, datetime.timedelta(hours=4))

    # TODO test inheritance after set and delete of attrs


#===========================================
# This mocks the django.modulestore() function and is intended purely to disentangle
# the tests from django
def modulestore(name='default'):
    def load_function(path):
        module_path, _, name = path.rpartition('.')
        return getattr(import_module(module_path), name)

    if name not in SplitModuleTest._MODULESTORES:
        class_ = load_function(SplitModuleTest.MODULESTORE[name]['ENGINE'])

        options = {}

        options.update(SplitModuleTest.MODULESTORE[name]['OPTIONS'])
        options['render_template'] = render_to_template_mock

        SplitModuleTest._MODULESTORES[name] = class_(
            **options
        )

    return SplitModuleTest._MODULESTORES[name]


def render_to_template_mock(*args):
    pass
