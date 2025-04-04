import { TestFixture, type Config } from '../../../test/WebsitesFixture';

const config: Config = {
    plugin: {
        id: 'tenshiid',
        title: 'Tenshi.ID'
    },
    container: {
        url: 'https://tenshi01.id/komik/a-bad-person/',
        id: '/komik/a-bad-person/',
        title: 'A Bad Person'
    },
    child: {
        id: '/a-bad-person-chapter-01-bahasa-indonesia/',
        title: 'Chapter 01',
        timeout: 15000
    },
    entry: {
        index: 0,
        size: 70_363,
        type: 'image/jpeg'
    }
};

new TestFixture(config).AssertWebsite();